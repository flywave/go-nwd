package nwd

import (
	"fmt"
)

// TreeNode is a decoded model-tree node (PartitionNode /
// GroupModelItemNode / GeometryModelItemNode).
type TreeNode struct {
	TypeID      int         `json:"type_id"`
	TypeName    string      `json:"type_name"`
	UserName    string      `json:"user_name,omitempty"`
	ClassName   string      `json:"class_name,omitempty"`
	DisplayName string      `json:"display_name,omitempty"`
	Name        string      `json:"name,omitempty"`
	Flags       uint32      `json:"flags,omitempty"`
	GuidIndex   uint32      `json:"guid_index,omitempty"`
	ModelType   *uint32     `json:"model_type,omitempty"`
	Usage       *int32      `json:"usage,omitempty"`
	Transform   *Transform  `json:"transform,omitempty"`
	Children    []*TreeNode `json:"children,omitempty"`
	AttrCount   int         `json:"attr_count,omitempty"`
}

// Tree is the root result of decoding a partition stream.
type Tree struct {
	Root *TreeNode `json:"root"`
	// Objects is the total envelope count including Name/attributes.
	Objects int `json:"objects"`
}

// PartitionRoot is the identification of a real partition stream's root
// object, decoded without walking the full attribute graph. Verified
// against a real NWD (findings N40/N42).
type PartitionRoot struct {
	UserName    string `json:"user_name"`
	ClassName   string `json:"class_name"`
	DisplayName string `json:"display_name,omitempty"`
	ModelType   uint32 `json:"model_type"`
	AttrFlags   uint32 `json:"flags"`
	GuidIndex   uint32 `json:"guid_index"`
	AttrCount   uint32 `json:"attr_count"`
	// FirstAttrType is the first attribute typeID encountered, if any.
	FirstAttrType int `json:"first_attr_type,omitempty"`
}

// DecodePartitionRoot decodes a partition stream's root PartitionNode
// header (envelope + modelType + ModelBase + ModelItem header) without
// requiring decoders for the trailing attribute objects. This works on
// real files where the attribute payloads are not yet fully decoded.
func DecodePartitionRoot(stream []byte) (*PartitionRoot, error) {
	or := NewObjectReader(stream, formatVersionGate)
	marker, err := or.r.u32()
	if err != nil {
		return nil, err
	}
	if marker != envNewBase {
		return nil, fmt.Errorf("nwd: partition root marker %d != %d", marker, envNewBase)
	}
	typeID, err := or.r.u32()
	if err != nil {
		return nil, err
	}
	if typeID != PartitionNode {
		return nil, fmt.Errorf("nwd: partition root type %d != %d", typeID, PartitionNode)
	}
	root := &PartitionRoot{}
	// Reserve the root's vector slot so nested envelopes index correctly
	// (root occupies slot 0; its Name object is slot 1).
	or.vector = append(or.vector, ObjectRef{Kind: 2, Index: 0, TypeID: int(typeID)})
	if root.ModelType, err = or.r.u32(); err != nil {
		return nil, err
	}
	// ModelBase: userName string + Name object.
	if root.UserName, err = or.r.readString(); err != nil {
		return nil, err
	}
	nameObj, err := or.ReadObject()
	if err != nil {
		return nil, fmt.Errorf("nwd: root class name: %w", err)
	}
	if nameObj != nil && nameObj.TypeID == TypeName {
		root.ClassName = nameObj.Name
		root.DisplayName = nameObj.DisplayName
	}
	if root.AttrFlags, err = or.r.u32(); err != nil {
		return nil, err
	}
	if root.GuidIndex, err = or.r.u32(); err != nil {
		return nil, err
	}
	if root.AttrCount, err = or.r.u32(); err != nil {
		return nil, err
	}
	// Peek the first attribute typeID, if any.
	if root.AttrCount > 0 {
		am, err := or.r.u32()
		if err == nil {
			if am == envNewBase+2 { // next new object after root(slot0)+name(slot1)
				if at, err := or.r.u32(); err == nil {
					root.FirstAttrType = int(at)
				}
			}
		}
	}
	return root, nil
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
		Transform: o.Transform,
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
	Total   int         `json:"total"`
	ByType  map[int]int `json:"by_type"`
	Stopped *Object     `json:"stopped_at,omitempty"`
	Err     error       `json:"-"`
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
