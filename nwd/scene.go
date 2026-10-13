package nwd

// SceneInstance is one placement in the assembled scene: a tree node with
// a world transform and an optional triangle mesh.
type SceneInstance struct {
	Name      string       `json:"name"`
	Path      []string     `json:"path"`
	Transform *Transform   `json:"transform,omitempty"`
	Mesh      *Mesh        `json:"mesh,omitempty"`
	HasMesh   bool         `json:"has_mesh"`
}

// Scene is the assembled model: a flat list of instances produced by
// walking the partition tree (M6).
type Scene struct {
	Instances []SceneInstance `json:"instances"`
	Nodes     int             `json:"nodes"`
	WithMesh  int             `json:"with_mesh"`
}

// BuildScene walks a decoded partition tree and emits one instance per
// node that carries a transform; the optional mesh is attached to every
// instance when supplied (single-geometry fixture; per-node geometry
// binding is U16).
func BuildScene(tree *Tree, mesh *Mesh) *Scene {
	s := &Scene{}
	var walk func(n *TreeNode, path []string)
	walk = func(n *TreeNode, path []string) {
		s.Nodes++
		p := append(append([]string{}, path...), n.Name)
		if n.UserName != "" {
			p = append(append([]string{}, path...), n.UserName)
		}
		if n.Transform != nil || mesh != nil {
			inst := SceneInstance{
				Name:      nodeName(n),
				Path:      p,
				Transform: n.Transform,
			}
			if mesh != nil {
				inst.Mesh = mesh
				inst.HasMesh = true
				s.WithMesh++
			}
			s.Instances = append(s.Instances, inst)
		}
		for _, c := range n.Children {
			walk(c, p)
		}
	}
	if tree != nil && tree.Root != nil {
		walk(tree.Root, nil)
	}
	return s
}

func nodeName(n *TreeNode) string {
	if n.UserName != "" {
		return n.UserName
	}
	if n.DisplayName != "" {
		return n.DisplayName
	}
	return n.Name
}
