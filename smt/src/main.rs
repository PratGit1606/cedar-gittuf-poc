//! Two SMT proofs about policies emitted by the Go compiler (`gcedar compile`),
//! checked with cedar-policy-symcc and cvc5. Run via `smt/run.sh`.
//!
//! Every query states its expected outcome; the program prints the actual
//! outcome (a solver counterexample, or "unsat" = the property holds for all
//! well-typed inputs) and exits non-zero if any outcome differs from the
//! expectation. Each counterexample is replayed through Cedar's concrete
//! authorizer on both policy sets as a sanity check.

use std::{env, fs, path::Path, process::ExitCode, str::FromStr};

use cedar_policy::{Authorizer, Decision, PolicySet, Schema};
use cedar_policy_symcc::{solver::LocalSolver, CedarSymCompiler, CompiledPolicySet, Env};

/// Analysis-only policy: restricts a query to requests on refs/heads/main by
/// denying everything else. Appended to BOTH sides of a scoped query; it is
/// part of the question, not of the policies under test.
const SCOPE_MAIN: &str =
    "forbid(principal, action, resource) unless { resource.name == \"refs/heads/main\" };\n";

/// Analysis-only policy for proof 2: "the request has the author among the approvals".
const AUTHOR_IN_APPROVALS: &str =
    "permit(principal, action, resource) when { context.approvals.contains(context.author) };\n";

#[derive(Clone, Copy, PartialEq, Debug)]
enum Expect {
    Holds,
    Counterexample,
}

enum Kind {
    /// every request allowed by A is allowed by B
    Implies,
    /// A and B decide every request the same way
    Equivalent,
    /// no request is allowed by both A and B
    Disjoint,
}

struct Query {
    title: &'static str,
    kind: Kind,
    a: &'static str, // compiled policy dir name
    b: &'static str, // compiled policy dir name, or literal policy text starting with "permit"/"forbid"
    scope_main: bool,
    expect: Expect,
}

fn load(out: &Path, name: &str) -> (String, String) {
    let d = out.join(name);
    let p = fs::read_to_string(d.join("policies.cedar")).unwrap_or_else(|e| panic!("{}: {e}", d.display()));
    let s = fs::read_to_string(d.join("schema.cedarschema")).unwrap();
    (p, s)
}

fn decide(ps: &PolicySet, cex: &Env) -> Decision {
    Authorizer::new().is_authorized(&cex.request, ps, &cex.entities).decision()
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let out = env::args().nth(1).expect("usage: gcedar-smt <compiled-dir>");
    let out = Path::new(&out);
    let q = |title, kind, a, b, scope_main, expect| Query {
        title,
        kind,
        a,
        b,
        scope_main,
        expect,
    };
    use Expect::*;
    use Kind::*;
    let queries = vec![
        // ---- Proof 1 (gittuf mode): a broad rule weakens a narrow one ----
        q("P1  [narrow+broad] allows only what [narrow] allows?  (broad refs/heads/* 1-of-{alice})",
          Implies, "p1_broad", "p1_narrow", false, Counterexample),
        q("P1  on refs/heads/main: [narrow] allows only what [narrow+broad] allows?",
          Implies, "p1_narrow", "p1_broad", true, Holds),
        q("P1  over ALL refs: [narrow] allows only what [narrow+broad] allows?",
          Implies, "p1_narrow", "p1_broad", false, Counterexample),
        // ---- Proof 1 controls ----
        q("C1a disjoint rule (refs/heads/dev): on main, [narrow] == [narrow+dev]?",
          Equivalent, "p1_narrow", "p1_disjoint", true, Holds),
        q("C1b disjoint rule: [narrow+dev] allows only what [narrow] allows (no weakening anywhere)?",
          Implies, "p1_disjoint", "p1_narrow", false, Holds),
        q("C1c disjoint rule over ALL refs: [narrow] == [narrow+dev]?",
          Equivalent, "p1_narrow", "p1_disjoint", false, Counterexample),
        q("C1d broad, same threshold and members (refs/heads/* 2-of-{alice,bob}): no weakening?",
          Implies, "p1_broad_same", "p1_narrow", false, Holds),
        q("C1e broad, higher threshold (refs/heads/* 3-of-{alice,bob,carol}): no weakening?",
          Implies, "p1_broad_higher", "p1_narrow", false, Holds),
        q("C1f broad, same threshold, other members (refs/heads/* 2-of-{alice,carol}): no weakening?",
          Implies, "p1_broad_same_k_other", "p1_narrow", false, Counterexample),
        // ---- Proof 2 (strict mode): forbid_self_approval ----
        q("P2  with forbid_self_approval: no request with author in approvals is allowed?",
          Disjoint, "p2_forbid", AUTHOR_IN_APPROVALS, false, Holds),
        q("C2  without the forbid: no request with author in approvals is allowed?",
          Disjoint, "p2_noforbid", AUTHOR_IN_APPROVALS, false, Counterexample),
    ];

    let mut compiler = CedarSymCompiler::new(LocalSolver::cvc5().expect("cvc5 (set CVC5=path)"))
        .expect("solver");
    let mut failures = 0;
    for qu in &queries {
        let (pa, schema_text) = load(out, qu.a);
        let pb = if qu.b.starts_with("permit") || qu.b.starts_with("forbid") {
            qu.b.to_string()
        } else {
            let (p, s) = load(out, qu.b);
            assert_eq!(s, schema_text, "{}: both sides must share a schema", qu.title);
            p
        };
        let (pa, pb) = if qu.scope_main {
            (pa + SCOPE_MAIN, pb + SCOPE_MAIN)
        } else {
            (pa, pb)
        };
        let schema = Schema::from_cedarschema_str(&schema_text).expect("schema").0;
        let psa = PolicySet::from_str(&pa).expect("policy set A");
        let psb = PolicySet::from_str(&pb).expect("policy set B");

        println!("\n=== {}", qu.title);
        let mut got = Expect::Holds;
        for req_env in schema.request_envs() {
            let ca = CompiledPolicySet::compile(&psa, &req_env, &schema).expect("symcc compile A");
            let cb = CompiledPolicySet::compile(&psb, &req_env, &schema).expect("symcc compile B");
            let cex = match qu.kind {
                Implies => compiler.check_implies_with_counterexample_opt(&ca, &cb).await,
                Equivalent => compiler.check_equivalent_with_counterexample_opt(&ca, &cb).await,
                Disjoint => compiler.check_disjoint_with_counterexample_opt(&ca, &cb).await,
            }
            .expect("solver call");
            match cex {
                None => println!(
                    "unsat: holds for every well-typed request ({} / {} / {})",
                    req_env.principal(),
                    req_env.action(),
                    req_env.resource()
                ),
                Some(cex) => {
                    got = Expect::Counterexample;
                    let (da, db) = (decide(&psa, &cex), decide(&psb, &cex));
                    println!("counterexample:\n{cex}");
                    println!("replayed in Cedar: A={da:?} B={db:?}");
                    let consistent = match qu.kind {
                        Implies => da == Decision::Allow && db == Decision::Deny,
                        Equivalent => da != db,
                        Disjoint => da == Decision::Allow && db == Decision::Allow,
                    };
                    if !consistent {
                        println!("!! counterexample does not replay as expected");
                        failures += 1;
                    }
                }
            }
        }
        let ok = got == qu.expect;
        println!("expected {:?}, got {:?}: {}", qu.expect, got, if ok { "OK" } else { "MISMATCH" });
        if !ok {
            failures += 1;
        }
    }
    println!("\n{} queries, {} failures", queries.len(), failures);
    if failures == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
