package nwd

import (
	"fmt"
)

// TreeNode is a decoded model-tree node (PartitionNode /
// GroupModelItemNode / GeometryModelItemNode).
type TreeNode struct {
	TypeID      int    `json:"type_id"`
	TypeName    string `json:"type_name"`
	UserName    string `json:"user_name,omitempty"`
	ClassName   string `json:"class_name,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	Name        string `json:"name,omitempty"`
	Flags       uint32 `json:"flags,omitempty"`
	GuidIndex   uint32 `json:"guid_index,omitempty"`
	ModelType   *uint32 `json:"model_type,omitempty"`
	Usage       *int32  `json:"usage,omitempty"`
	Children    []*TreeNode `json:"children,omitempty"`
	AttrCount   int     `json:"attr_count,omitempty"`
}

// Tree is the root result of decoding a partition stream.
type Tree struct {
	Root *TreeNode `json:"root"`
	// Objects is the total envelope count including Name/attributes.
	Objects int `json:"objects"`
}

// formatVersionGate is the FormatVersionEx value assumed by the go-nwd
// decoders: must sit in the (21, 248] window where both ModelBase and
// the un-gated ModelItem paths apply (findings N22, U10).
const formatVersionGate = 100

// DecodeTree decodes a partition logical stream's object sequence into a
// tree. The first non-nil object must be a PartitionNode (type 32), which
// is what OdNwPartitionStreamLoader::parseStream expects (ecx=0x20).
func DecodeTree(stream []byte) (*Tree, error) {
	or := NewObjectReader(stream, formatVersionGate)
	var root *Object
	count := 0
	for {
		obj, err := or.ReadObject()
		if err != nil {
			return nil, fmt.Errorf("nwd: object %d: %w", count, err)
		}
		if obj == nil {
			break
		}
		count++
		if root == nil {
			if obj.TypeID != PartitionNode {
				return nil, fmt.Errorf("nwd: partition stream root type %d (%s), want %d PartitionNode",
					obj.TypeID, obj.TypeName, PartitionNode)
			}
			root = obj
		}
		if or.Remaining() == 0 {
			break
		}
	}
	if root == nil {
		return nil, fmt.Errorf("nwd: empty partition stream")
	}
	return &Tree{Root: objToNode(root), Objects: count}, nil
}

func objToNode(o *Object) *TreeNode {
	n := &TreeNode{
		TypeID:    o.TypeID,
		TypeName:  o.TypeName,
		UserName:  o.UserName,
		Flags:     o.Flags,
		GuidIndex: o.GuidIndex,
		ModelType: o.ModelType,
		Usage:     o.Usage,
		AttrCount: len(o.Attributes),
	}
	if o.ClassName != nil {
		n.ClassName = o.ClassName.Name
		n.DisplayName = o.ClassName.DisplayName
	}
	if o.TypeID == TypeName {
		n.Name = o.Name
		n.DisplayName = o.DisplayName
	}
	for _, c := range o.Children {
		n.Children = append(n.Children, objToNode(c))
	}
	return n
}

// Census walks a logical stream and counts envelope types without full
// payload decoding for unsupported types. Unsupported types stop the walk
// at their payload (no length framing) and are reported in Err.
type Census struct {
	Total   int            `json:"total"`
	ByType  map[int]int    `json:"by_type"`
	Stopped *Object        `json:"stopped_at,omitempty"`
	Err     error          `json:"-"`
}

// CensusStream counts object envelopes until nil, end, or an
// unsupported type payload.
func CensusStream(stream []byte, formatVersion uint32) *Census {
	or := NewObjectReader(stream, formatVersion)
	c := &Census{ByType: map[int]int{}}
	for {
		obj, err := or.ReadObject()
		if err != nil {
			c.Err = err
			return c
		}
		if obj == nil {
			return c
		}
		c.Total++
		c.ByType[obj.TypeID]++
		if or.Remaining() == 0 {
			return c
		}
	}
}
