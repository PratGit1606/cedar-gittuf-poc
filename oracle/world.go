// Package oracle materializes delegation documents as real gittuf policies in
// throwaway Git repositories and asks gittuf's own verifier for a verdict.
//
// Everything goes through gittuf's public experimental/gittuf API (the same
// code paths as the gittuf CLI): trust init, policy init, add-key, add-rule,
// policy apply, rsl record, attest authorize, verify-ref.
package oracle

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/gittuf/gittuf/experimental/gittuf"
	attestopts "github.com/gittuf/gittuf/experimental/gittuf/options/attest"
	rslopts "github.com/gittuf/gittuf/experimental/gittuf/options/rsl"
	verifyopts "github.com/gittuf/gittuf/experimental/gittuf/options/verify"
)

// Key is an ed25519 SSH key pair on disk.
type Key struct {
	Name    string
	Private string // path
	Public  string // path
	PEM     []byte
	ID      string // gittuf principal ID (SSH key ID)
}

var (
	keyMu    sync.Mutex
	keyDir   string
	keyCache = map[string]*Key{}
)

// GetKey returns a deterministic-by-name key, generating it once per process.
func GetKey(name string) (*Key, error) {
	keyMu.Lock()
	defer keyMu.Unlock()
	if k, ok := keyCache[name]; ok {
		return k, nil
	}
	if keyDir == "" {
		d, err := os.MkdirTemp("", "oracle-keys-")
		if err != nil {
			return nil, err
		}
		keyDir = d
	}
	priv := filepath.Join(keyDir, name)
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", priv).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("ssh-keygen: %v: %s", err, out)
	}
	pem, err := os.ReadFile(priv)
	if err != nil {
		return nil, err
	}
	p, err := gittuf.LoadPublicKey(priv + ".pub")
	if err != nil {
		return nil, err
	}
	k := &Key{Name: name, Private: priv, Public: priv + ".pub", PEM: pem, ID: p.ID()}
	keyCache[name] = k
	return k, nil
}

// one builds a single-element slice without naming the (internal) element type.
func one[T any](x T) []T { return []T{x} }

// World is a fresh Git repository with gittuf initialised.
type World struct {
	Dir  string
	Repo *gittuf.Repository
	Root *Key
	ctx  context.Context
	n    int
}

func git(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out)), nil
}

// NewWorld creates a repository with one commit on main and an empty gittuf
// root of trust plus a "targets" rule file. The root key also acts as the
// policy key.
func NewWorld(dir string) (*World, error) {
	for _, args := range [][]string{
		{"init", "-q", "-b", "main"},
		{"config", "user.name", "oracle"},
		{"config", "user.email", "oracle@example.invalid"},
		{"commit", "-q", "--allow-empty", "-m", "initial"},
	} {
		if _, err := git(dir, args...); err != nil {
			return nil, err
		}
	}
	repo, err := gittuf.LoadRepository(dir)
	if err != nil {
		return nil, err
	}
	root, err := GetKey("root")
	if err != nil {
		return nil, err
	}
	w := &World{Dir: dir, Repo: repo, Root: root, ctx: context.Background()}
	s, err := gittuf.LoadSigner(repo, root.Private)
	if err != nil {
		return nil, err
	}
	rootPub, err := gittuf.LoadPublicKey(root.Public)
	if err != nil {
		return nil, err
	}
	if err := repo.InitializeRoot(w.ctx, s, false); err != nil {
		return nil, fmt.Errorf("trust init: %w", err)
	}
	if err := repo.AddTopLevelTargetsKey(w.ctx, s, rootPub, false); err != nil {
		return nil, fmt.Errorf("add-policy-key: %w", err)
	}
	if err := repo.InitializeTargets(w.ctx, s, "targets", false); err != nil {
		return nil, fmt.Errorf("policy init: %w", err)
	}
	return w, nil
}

// AddKeys adds SSH keys as principals to a rule file.
func (w *World) AddKeys(ruleFile string, keys ...*Key) error {
	s, err := gittuf.LoadSigner(w.Repo, w.Root.Private)
	if err != nil {
		return err
	}
	for _, k := range keys {
		p, err := gittuf.LoadPublicKey(k.Public)
		if err != nil {
			return err
		}
		if err := w.Repo.AddPrincipalToTargets(w.ctx, s, ruleFile, one(p), false); err != nil {
			return fmt.Errorf("add principal %s: %w", k.Name, err)
		}
	}
	return nil
}

// AddRule appends a rule (gittuf: delegation) to a rule file.
func (w *World) AddRule(ruleFile, name string, principalIDs, patterns []string, threshold int) error {
	s, err := gittuf.LoadSigner(w.Repo, w.Root.Private)
	if err != nil {
		return err
	}
	return w.Repo.AddDelegation(w.ctx, s, ruleFile, name, principalIDs, patterns, threshold, false)
}

// Apply stages and applies the policy (gittuf policy stage/apply --local-only).
func (w *World) Apply() error {
	if err := w.Repo.StagePolicy(w.ctx, "", true, false); err != nil {
		return fmt.Errorf("policy stage: %w", err)
	}
	if err := w.Repo.ApplyPolicy(w.ctx, "", true, false); err != nil {
		return fmt.Errorf("policy apply: %w", err)
	}
	return nil
}

// Push simulates an update of ref to a new commit:
//  1. a new commit is made on a scratch feature branch and recorded in the RSL,
//  2. each key in attestors signs a reference authorization for ref -> that commit,
//  3. ref is fast-forwarded and an RSL entry for ref is recorded, signed by
//     pusher (or unsigned if pusher is nil).
//
// It returns gittuf's verdict on the latest entry for ref (nil = allowed).
func (w *World) Push(ref string, pusher *Key, attestors []*Key) (error, error) {
	w.n++
	feature := fmt.Sprintf("refs/heads/oracle-feature-%d", w.n)
	base := ref
	if _, err := git(w.Dir, "rev-parse", "--verify", "-q", ref); err != nil {
		base = "refs/heads/main"
	}
	if _, err := git(w.Dir, "update-ref", feature, base); err != nil {
		return nil, err
	}
	if _, err := git(w.Dir, "symbolic-ref", "HEAD", feature); err != nil {
		return nil, err
	}
	if _, err := git(w.Dir, "commit", "-q", "--allow-empty", "-m", fmt.Sprintf("change %d", w.n)); err != nil {
		return nil, err
	}
	if _, err := git(w.Dir, "symbolic-ref", "HEAD", "refs/heads/main"); err != nil {
		return nil, err
	}
	if err := w.Repo.RecordRSLEntryForReference(w.ctx, feature, false, rslopts.WithRecordLocalOnly()); err != nil {
		return nil, fmt.Errorf("rsl record feature: %w", err)
	}
	for _, a := range attestors {
		s, err := gittuf.LoadSigner(w.Repo, a.Private)
		if err != nil {
			return nil, err
		}
		if err := w.Repo.AddReferenceAuthorization(w.ctx, s, ref, feature, false, attestopts.WithRSLEntry()); err != nil {
			return nil, fmt.Errorf("attest authorize by %s: %w", a.Name, err)
		}
	}
	if _, err := git(w.Dir, "update-ref", ref, feature); err != nil {
		return nil, err
	}
	opts := []rslopts.RecordOption{rslopts.WithRecordLocalOnly()}
	if pusher != nil {
		opts = append(opts, rslopts.WithRecordSigningKeyBytes(pusher.PEM))
	}
	if err := w.Repo.RecordRSLEntryForReference(w.ctx, ref, pusher != nil, opts...); err != nil {
		return nil, fmt.Errorf("rsl record %s: %w", ref, err)
	}
	return w.Repo.VerifyRef(w.ctx, ref, verifyopts.WithLatestOnly()), nil
}

var (
	binOnce sync.Once
	binPath string
	binErr  error
)

// gittufBin builds the gittuf CLI from the sibling clone (once per process).
func gittufBin() (string, error) {
	binOnce.Do(func() {
		d, err := os.MkdirTemp("", "oracle-bin-")
		if err != nil {
			binErr = err
			return
		}
		binPath = filepath.Join(d, "gittuf")
		src, _ := filepath.Abs("../../gittuf")
		cmd := exec.Command("go", "build", "-o", binPath, ".")
		cmd.Dir = src
		if out, err := cmd.CombinedOutput(); err != nil {
			binErr = fmt.Errorf("build gittuf: %v: %s", err, out)
		}
	})
	return binPath, binErr
}

// AddPerson adds a tufv02 person (one ID, possibly several keys) using the
// gittuf CLI, since the public Go API needs internal types to build a person.
func (w *World) AddPerson(ruleFile, personID string, keys ...*Key) error {
	bin, err := gittufBin()
	if err != nil {
		return err
	}
	// The CLI signs policy commits, so Git signing must be configured.
	for _, kv := range [][2]string{{"gpg.format", "ssh"}, {"user.signingkey", w.Root.Private}} {
		if _, err := git(w.Dir, "config", kv[0], kv[1]); err != nil {
			return err
		}
	}
	args := []string{"policy", "add-person", "-k", w.Root.Private, "--policy-name", ruleFile, "--person-ID", personID}
	for _, k := range keys {
		args = append(args, "--public-key", k.Public)
	}
	cmd := exec.Command(bin, args...)
	cmd.Dir = w.Dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("gittuf policy add-person: %v: %s", err, out)
	}
	return nil
}
