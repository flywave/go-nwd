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
		Tree             *nwd.Tree             `json:"tree,omitempty"`
		PartitionRoot    *nwd.PartitionRoot    `json:"partition_root,omitempty"`
		PartitionObjects *nwd.ObjectStream     `json:"partition_objects,omitempty"`
		Mesh             *nwd.Mesh             `json:"mesh,omitempty"`
		Schemas          []nwd.Schema          `json:"schemas,omitempty"`
		Scene            *nwd.Scene            `json:"scene,omitempty"`
		PropertyNames    []nwd.NameRecord      `json:"property_names,omitempty"`
		Geometry         *geomSummary          `json:"geometry,omitempty"`
		Fragments        *fragSummary          `json:"fragments,omitempty"`
		Validation       *nwd.MeshStats        `json:"validation,omitempty"`
		LogicalTree      *nwd.LogicalHierarchy `json:"logical_tree,omitempty"`
		Guids            []string              `json:"guids,omitempty"`
	}{Metadata: f.Metadata}

	if idx := f.StreamByName("LcOpNwdPartition"); idx >= 0 {
		if root, err := f.DecodePartitionRoot(idx); err == nil {
			out.PartitionRoot = root
		}
		if objs, err := f.DecodeObjectStream(idx, 451, 8); err == nil && len(objs.Objects) > 0 {
			out.PartitionObjects = objs
		}
		tree, err := f.DecodeTree(idx)
		if err != nil {
			fmt.Fprintln(os.Stderr, "note: full tree decode:", err)
		} else {
			out.Tree = tree
		}
	}

	// LogicalHierarchy: model browser tree (U19) + PartitionProps block
	// mapping + GuidStore (findings N117/N118).
	if idx := f.StreamByName("LcOpNwdLogicalHierarchy"); idx >= 0 {
		if h, err := f.DecodeLogicalHierarchyStream(idx, f.StreamByName("LcOaPartitionProps") >= 0); err == nil {
			out.LogicalTree = h
		} else {
			fmt.Fprintln(os.Stderr, "note: logical hierarchy:", err)
		}
	}
	if idx := f.StreamByName("LcOpGuidStore"); idx >= 0 {
		if data, err := f.StreamData(idx); err == nil {
			if guids, err := nwd.DecodeGuidStore(data); err == nil {
				out.Guids = guids
			}
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

	// Assemble a flat scene from the tree + mesh (M6).
	if out.Tree != nil {
		out.Scene = nwd.BuildScene(out.Tree, out.Mesh)
	}

	// Extract property keys from the CDA property stream (best-effort).
	if idx := f.StreamByName("LcOaPartitionProps"); idx >= 0 {
		if names, err := f.ScanStreamNames(idx, 4000); err == nil && len(names) > 0 {
			out.PropertyNames = names
		}
	}

	// Geometry stream: elements, faces and vertices via the deterministic
	// element decoder (findings N74-N94).
	if idx := f.StreamByName("LcOpNwdGeometry"); idx >= 0 {
		if data, err := f.StreamData(idx); err == nil {
			els := nwd.DecodeElements(data, 0)
			g := &geomSummary{Elements: len(els)}
			for _, e := range els {
				g.Vertices += len(e.Vertices)
				if e.FacesFound {
					g.FaceElements++
					g.Faces += len(e.PerFace)
				}
			}
			if len(els) > 0 {
				g.SampleElement = els[0].ElementType
				g.SampleVertices = len(els[0].Vertices)
				if len(els[0].Vertices) > 0 {
					g.FirstVertex = els[0].Vertices[0][:]
				}
			}
			out.Geometry = g
		} else {
			fmt.Fprintln(os.Stderr, "note: geometry:", err)
		}
	}

	// Fragments stream: placement transforms and geometry links (N95-N109).
	if idx := f.StreamByName(nwd.StreamFragments); idx >= 0 {
		if data, err := f.StreamData(idx); err == nil {
			recs := nwd.DecodeFragments(data)
			fs := &fragSummary{Fragments: len(recs)}
			for _, r := range recs {
				if r.Transform != nil {
					fs.WithTransform++
				}
				if r.GeomIndex > 0 {
					fs.WithGeomIndex++
				}
			}
			out.Fragments = fs
		}
	}

	// Mesh consistency invariants (N97/N98).
	if idx := f.StreamByName("LcOpNwdGeometry"); idx >= 0 {
		if data, err := f.StreamData(idx); err == nil {
			st := nwd.ValidateMesh(nwd.DecodeMesh(data, 0))
			out.Validation = &st
		}
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

type fragSummary struct {
	Fragments     int `json:"fragments"`
	WithTransform int `json:"with_transform"`
	WithGeomIndex int `json:"with_geometry_index"`
}

type geomSummary struct {
	Elements       int       `json:"elements"`
	FaceElements   int       `json:"face_elements"`
	Faces          int       `json:"faces"`
	Vertices       int       `json:"vertices"`
	SampleElement  int       `json:"sample_element_type"`
	SampleVertices int       `json:"sample_vertex_count"`
	FirstVertex    []float64 `json:"first_vertex,omitempty"`
}
