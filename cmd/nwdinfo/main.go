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
		Tree    *nwd.Tree    `json:"tree,omitempty"`
		Mesh    *nwd.Mesh    `json:"mesh,omitempty"`
		Schemas []nwd.Schema `json:"schemas,omitempty"`
	}{Metadata: f.Metadata}

	if idx := f.StreamByName("LcOpNwdPartition"); idx >= 0 {
		tree, err := f.DecodeTree(idx)
		if err != nil {
			fmt.Fprintln(os.Stderr, "warning: partition tree:", err)
		} else {
			out.Tree = tree
		}
	}

	// GeometryCompress: decode blocks and assemble a mesh when block 0/1
	// hold a vertex set and an index list (uncompressed path, M4).
	if idx := f.StreamByName("LcOpNwdGeometryCompress"); idx >= 0 {
		if blocks, err := f.DecodeGeometryBlocks(idx); err == nil && len(blocks) >= 2 {
			if m, err := nwd.BuildMesh(blocks[0].Data, blocks[1].Data); err == nil {
				out.Mesh = m
			}
		}
	}

	// CommonSchemas: CDA property definitions (M5).
	for _, name := range []string{"LcOpNwdCommonSchemas", "LcOaCommonSchemas"} {
		if idx := f.StreamByName(name); idx >= 0 {
			if schemas, err := f.DecodeSchemas(idx); err == nil {
				out.Schemas = schemas
			} else {
				fmt.Fprintln(os.Stderr, "warning: schemas:", err)
			}
			break
		}
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
