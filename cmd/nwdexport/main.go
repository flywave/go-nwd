// nwdexport converts a Navisworks .nwd file's tessellated geometry directly to
// MST or glTF, mirroring the go-rvm export workflow.
//
//	nwdexport <file.nwd> [output_prefix] [--format=mst|gltf|both] [--gltf-format=glb|gltf]
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/flywave/go-nwd/export"
	"github.com/flywave/go-nwd/nwd"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: nwdexport <file.nwd> [output_prefix] [--format=mst|gltf|both] [--gltf-format=glb|gltf]")
		os.Exit(1)
	}
	input := os.Args[1]
	prefix := "output"
	format := "mst"
	gltfBinary := true
	for _, a := range os.Args[2:] {
		switch {
		case strings.HasPrefix(a, "--format="):
			format = strings.TrimPrefix(a, "--format=")
		case strings.HasPrefix(a, "--gltf-format="):
			gltfBinary = strings.TrimPrefix(a, "--gltf-format=") != "gltf"
		case strings.HasPrefix(a, "--"):
			fmt.Fprintln(os.Stderr, "unknown option:", a)
			os.Exit(1)
		default:
			prefix = a
		}
	}
	if format != "mst" && format != "gltf" && format != "both" {
		fmt.Fprintln(os.Stderr, "invalid --format (want mst|gltf|both)")
		os.Exit(1)
	}

	buf, err := os.ReadFile(input)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read:", err)
		os.Exit(1)
	}
	f, err := nwd.Open(buf)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open:", err)
		os.Exit(1)
	}
	gi := f.StreamByName("LcOpNwdGeometry")
	if gi < 0 {
		fmt.Fprintln(os.Stderr, "no geometry stream")
		os.Exit(1)
	}
	data, err := f.StreamData(gi)
	if err != nil {
		fmt.Fprintln(os.Stderr, "geometry:", err)
		os.Exit(1)
	}
	m := nwd.DecodeMesh(data, 0)
	fmt.Printf("decoded %d vertices, %d triangles, %d lines\n", len(m.Vertices), len(m.Triangles), len(m.Lines))

	if format == "mst" || format == "both" {
		p := prefix + ".mst"
		if err := export.WriteMST(p, m, [3]byte{200, 200, 200}); err != nil {
			fmt.Fprintln(os.Stderr, "mst:", err)
			os.Exit(1)
		}
		fmt.Println("wrote", p)
	}
	if format == "gltf" || format == "both" {
		p := prefix + ".glb"
		if !gltfBinary {
			p = prefix + ".gltf"
		}
		if err := export.WriteGLTF(p, m, gltfBinary, [3]float32{0.78, 0.78, 0.78}); err != nil {
			fmt.Fprintln(os.Stderr, "gltf:", err)
			os.Exit(1)
		}
		fmt.Println("wrote", p)
	}
}
