// Package export converts a reconstructed go-nwd mesh into interchange formats
// (MST and glTF), mirroring the direct-to-mesh approach used by go-rvm.
//
// NWD geometry is a tessellated display mesh (findings N71/N79), not BREP, so it
// is exported as triangle meshes rather than exact solids.
package export

import (
	"math"

	"github.com/flywave/gltf"
	"github.com/flywave/gltf/modeler"
	mst "github.com/flywave/go-mst"
	"github.com/flywave/go3d/vec3"

	"github.com/flywave/go-nwd/nwd"
)

// WriteMST writes a SceneMesh as a single MST file (one instance, one node).
func WriteMST(path string, m *nwd.SceneMesh, color [3]byte) error {
	node := &mst.MeshNode{Vertices: make([]vec3.T, len(m.Vertices))}
	for i, v := range m.Vertices {
		node.Vertices[i] = vec3.T{float32(v[0]), float32(v[1]), float32(v[2])}
	}
	if len(m.Triangles) > 0 {
		tri := &mst.MeshTriangle{Batchid: 0, Faces: make([]*mst.Face, 0, len(m.Triangles))}
		for _, t := range m.Triangles {
			tri.Faces = append(tri.Faces, &mst.Face{Vertex: [3]uint32{t[0], t[1], t[2]}})
		}
		node.FaceGroup = []*mst.MeshTriangle{tri}
		node.ReComputeNormal()
	}
	if len(m.Lines) > 0 {
		edges := make([][2]uint32, len(m.Lines))
		copy(edges, m.Lines)
		node.EdgeGroup = []*mst.MeshOutline{{Batchid: 0, Edges: edges}}
	}
	mesh := mst.NewMesh()
	bm := &mst.BaseMesh{
		Nodes:     []*mst.MeshNode{node},
		Materials: []mst.MeshMaterial{&mst.BaseMaterial{Color: color}},
	}
	mesh.Instances = []*mst.InstanceMesh{{
		Mesh: bm,
		BBox: node.GetBoundbox(),
	}}
	return mst.MeshWriteTo(path, mesh)
}

// WriteGLTF writes a SceneMesh as glTF (binary .glb when binary is true, else
// JSON .gltf).
func WriteGLTF(path string, m *nwd.SceneMesh, binary bool, color [3]float32) error {
	doc := gltf.NewDocument()

	positions := make([][3]float32, len(m.Vertices))
	for i, v := range m.Vertices {
		positions[i] = [3]float32{float32(v[0]), float32(v[1]), float32(v[2])}
	}
	posAcc := modeler.WritePosition(doc, positions)
	attrs := gltf.Attribute{gltf.POSITION: posAcc}

	if nrm := computeSmoothNormals(m); nrm != nil {
		attrs[gltf.NORMAL] = modeler.WriteNormal(doc, nrm)
	}

	prim := &gltf.Primitive{
		Attributes: attrs,
		Mode:       gltf.PrimitiveTriangles,
	}
	if len(m.Triangles) > 0 {
		indices := make([]uint32, 0, len(m.Triangles)*3)
		for _, t := range m.Triangles {
			indices = append(indices, t[0], t[1], t[2])
		}
		prim.Indices = gltf.Index(modeler.WriteIndices(doc, indices))
	}

	prims := []*gltf.Primitive{prim}
	if len(m.Lines) > 0 {
		lidx := make([]uint32, 0, len(m.Lines)*2)
		for _, e := range m.Lines {
			lidx = append(lidx, e[0], e[1])
		}
		prims = append(prims, &gltf.Primitive{
			Attributes: gltf.Attribute{gltf.POSITION: posAcc},
			Indices:    gltf.Index(modeler.WriteIndices(doc, lidx)),
			Mode:       gltf.PrimitiveLines,
		})
	}

	matIndex := uint32(len(doc.Materials))
	doc.Materials = append(doc.Materials, &gltf.Material{
		Name: "NWD",
		PBRMetallicRoughness: &gltf.PBRMetallicRoughness{
			BaseColorFactor: &[4]float32{color[0], color[1], color[2], 1.0},
			MetallicFactor:  gltf.Float(0),
			RoughnessFactor: gltf.Float(1),
		},
		DoubleSided: true,
	})
	prim.Material = gltf.Index(matIndex)

	meshIndex := uint32(len(doc.Meshes))
	doc.Meshes = append(doc.Meshes, &gltf.Mesh{
		Name:       "NWD",
		Primitives: prims,
	})
	nodeIndex := uint32(len(doc.Nodes))
	doc.Nodes = append(doc.Nodes, &gltf.Node{Name: "NWD", Mesh: gltf.Index(meshIndex)})
	doc.Scenes[0].Nodes = append(doc.Scenes[0].Nodes, nodeIndex)

	if binary {
		return gltf.SaveBinary(doc, path)
	}
	return gltf.Save(doc, path)
}

func computeSmoothNormals(m *nwd.SceneMesh) [][3]float32 {
	if len(m.Triangles) == 0 || len(m.Vertices) == 0 {
		return nil
	}
	acc := make([][3]float64, len(m.Vertices))
	for _, t := range m.Triangles {
		a, b, c := m.Vertices[t[0]], m.Vertices[t[1]], m.Vertices[t[2]]
		u := [3]float64{b[0] - a[0], b[1] - a[1], b[2] - a[2]}
		v := [3]float64{c[0] - a[0], c[1] - a[1], c[2] - a[2]}
		n := [3]float64{
			u[1]*v[2] - u[2]*v[1],
			u[2]*v[0] - u[0]*v[2],
			u[0]*v[1] - u[1]*v[0],
		}
		for k := 0; k < 3; k++ {
			acc[t[0]][k] += n[k]
			acc[t[1]][k] += n[k]
			acc[t[2]][k] += n[k]
		}
	}
	out := make([][3]float32, len(acc))
	for i, n := range acc {
		l := math.Sqrt(n[0]*n[0] + n[1]*n[1] + n[2]*n[2])
		if l == 0 {
			out[i] = [3]float32{0, 0, 1}
			continue
		}
		out[i] = [3]float32{float32(n[0] / l), float32(n[1] / l), float32(n[2] / l)}
	}
	return out
}
