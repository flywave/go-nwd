// nwdinfo prints identification metadata for a Navisworks .nwd file as JSON.
//
// Usage: nwdinfo <file.nwd>
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/flywave/go-nwd/nwd"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: nwdinfo <file.nwd>")
		os.Exit(2)
	}
	buf, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	f, err := nwd.Open(buf)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	out := struct {
		*nwd.Metadata
		Tree *nwd.Tree `json:"tree,omitempty"`
	}{Metadata: f.Metadata}

	if idx := f.StreamByName("LcOpNwdPartition"); idx >= 0 {
		tree, err := f.DecodeTree(idx)
		if err != nil {
			fmt.Fprintln(os.Stderr, "warning: partition tree:", err)
		} else {
			out.Tree = tree
		}
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
