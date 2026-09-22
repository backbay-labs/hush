// Command hushspec-normalize parses a HushSpec document and prints its own
// canonical form, for the cross-SDK comparison.
package main

import (
	"fmt"
	"os"

	hushspec "github.com/backbay-labs/hush/packages/go/hushspec"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: hushspec-normalize <path>")
		os.Exit(2)
	}

	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read %s: %v\n", os.Args[1], err)
		os.Exit(1)
	}

	spec, err := hushspec.Parse(string(data))
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse %s: %v\n", os.Args[1], err)
		os.Exit(1)
	}

	// The document's own canonical form: extends and merge_strategy are
	// resolution instructions, not policy (canonical spec 3).
	spec.Extends = nil
	spec.MergeStrategy = ""
	output, err := hushspec.CanonicalJSON(spec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to canonicalize %s: %v\n", os.Args[1], err)
		os.Exit(1)
	}

	fmt.Println(output)
}
