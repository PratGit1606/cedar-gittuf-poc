// Command gcedar compiles a delegation JSON document to Cedar.
//
//	gcedar compile doc.json              # policies to stdout
//	gcedar compile -out dir doc.json     # dir/policies.cedar, dir/schema.cedarschema, dir/meta.json
//	gcedar compile -mode gittuf doc.json # gittuf semantics (see gcedar.ModeGittuf)
//	gcedar demo                          # end-to-end example (port of demo.py)
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pratham/gcedar/gcedar"
)

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "demo" {
		demo()
		return
	}
	if len(os.Args) < 2 || os.Args[1] != "compile" {
		fmt.Fprintln(os.Stderr, "usage: gcedar compile [-mode strict|gittuf] [-out dir] doc.json | gcedar demo")
		os.Exit(2)
	}
	fs := flag.NewFlagSet("compile", flag.ExitOnError)
	out := fs.String("out", "", "write policies.cedar, schema.cedarschema and meta.json to this directory")
	mode := fs.String("mode", "strict", "compile mode: strict or gittuf")
	fs.Parse(os.Args[2:])
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: gcedar compile [-mode strict|gittuf] [-out dir] doc.json")
		os.Exit(2)
	}
	b, err := os.ReadFile(fs.Arg(0))
	check(err)
	var doc gcedar.Doc
	check(json.Unmarshal(b, &doc))
	c, err := gcedar.CompileMode(&doc, gcedar.Mode(*mode))
	check(err)
	if *out == "" {
		fmt.Print(c.Policies)
		return
	}
	check(os.MkdirAll(*out, 0o755))
	check(os.WriteFile(filepath.Join(*out, "policies.cedar"), []byte(c.Policies), 0o644))
	check(os.WriteFile(filepath.Join(*out, "schema.cedarschema"), []byte(c.Schema), 0o644))
	meta, _ := json.MarshalIndent(c.Meta, "", "  ")
	check(os.WriteFile(filepath.Join(*out, "meta.json"), meta, 0o644))
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "gcedar:", err)
		os.Exit(1)
	}
}
