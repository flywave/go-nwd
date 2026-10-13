// nwdgen writes a synthetic v8 NWD image to stdout (fixture utility).
package main

import (
	"os"

	"github.com/flywave/go-nwd/internal/nwstream"
	"github.com/flywave/go-nwd/nwd"
)

func main() {
	// Partition object stream (M3): root with two group children.
	tw := nwd.NewObjectWriter()
	tw.PartitionNode("Sample Project", "Building A", "IfcBuilding", 1, 0x7, 1)
	tw.GroupNode("Level 01", "IfcBuildingStorey", "Storey", 0x10, 2, 2, func(ow2 *nwd.ObjectWriter) {
		ow2.GroupNode("Room 101", "IfcSpace", "Office", 0, 3, 0, nil)
		ow2.GroupNode("Room 102", "IfcSpace", "Lab", 0, 4, 0, nil)
	})
	tw.GroupNode("Level 02", "IfcBuildingStorey", "Storey", 0x10, 5, 0, nil)
	tw.End()

	// GeometryCompress stream (M4): Blowfish-sealed blocks with a mesh.
	verts := [][3]float64{
		{0, 0, 0}, {4, 0, 0}, {4, 3, 0}, {0, 3, 0},
		{0, 0, 2}, {4, 0, 2}, {4, 3, 2}, {0, 3, 2},
	}
	tris := []uint32{
		0, 1, 2, 0, 2, 3, // bottom
		4, 6, 5, 4, 7, 6, // top
		0, 4, 5, 0, 5, 1, // sides
		1, 5, 6, 1, 6, 2,
		2, 6, 7, 2, 7, 3,
		3, 7, 4, 3, 4, 0,
	}
	geomBlocks, err := nwd.BuildGeometryBlocks([][]byte{
		nwd.EncodeVertexSet(verts),
		nwd.EncodeIndexList(tris),
	})
	if err != nil {
		panic(err)
	}

	// CommonSchemas stream (M5): CDA property definitions.
	schemaStream := nwd.EncodeSchemas([]nwd.Schema{{
		Name:        "LcOaNode",
		DisplayName: "Node",
		Concepts:    []string{"Common"},
		Fields: []nwd.SchemaField{
			{ID: "Name", DisplayName: "Name", Type: nwd.FieldString, Concepts: []string{"Identity"}},
			{ID: "Volume", DisplayName: "Volume", Type: nwd.FieldDouble},
			{ID: "IfcGuid", DisplayName: "GUID", Type: nwd.FieldGUID},
			{ID: "IsExternal", DisplayName: "Is External", Type: nwd.FieldBoolean},
		},
	}})

	img := nwstream.BuildSyntheticV8([]nwstream.SynthStream{
		{
			Name:   "LcOpNwdPartition",
			Middle: tw.Bytes(),
			Prefix: []byte{0x01, 0x00, 0x00, 0x00},
		},
		{
			Name:       "LcOpNwdSpatialHierarchy",
			Middle:     []byte("spatial-hierarchy-records"),
			Compressed: true,
		},
		{
			Name:   "LcOpNwdGeometryCompress",
			Middle: geomBlocks,
		},
		{
			Name:       "LcOpNwdCommonSchemas",
			Middle:     schemaStream,
			Compressed: true,
		},
	}, nil)
	if _, err := os.Stdout.Write(img); err != nil {
		os.Exit(1)
	}
}
