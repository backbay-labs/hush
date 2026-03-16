package main

import (
	"encoding/json"
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

	output, err := json.Marshal(spec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to serialize %s: %v\n", os.Args[1], err)
		os.Exit(1)
	}

	fmt.Println(string(output))
}
