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
	tw.PartitionNode("Sample Project", "Building A", "IfcBuilding", 1, 0x7, 1, 2, 0, func(ow *nwd.ObjectWriter) {
		ow.GroupNode("Level 01", "IfcBuildingStorey", "Storey", 0x10, 2, 2, func(ow2 *nwd.ObjectWriter) {
			ow2.GroupNode("Room 101", "IfcSpace", "Office", 0, 3, 0, nil)
			ow2.GroupNode("Room 102", "IfcSpace", "Lab", 0, 4, 0, nil)
		})
		ow.GroupNode("Level 02", "IfcBuildingStorey", "Storey", 0x10, 5, 0, nil)
	})
	tw.End()

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
			Name:       "LcOpNwdGeometryCompress",
			Middle:     []byte("geometry-compress-blocks"),
			Compressed: true,
		},
	}, nil)
	if _, err := os.Stdout.Write(img); err != nil {
		os.Exit(1)
	}
}
