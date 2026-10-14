package nwd

import "testing"

func TestScratchGateHouseWalk(t *testing.T) {
	g := openRealGateHouse(t)
	li := g.StreamByName("gatehouse.nwd\\LcOpNwdLogicalHierarchy")
	ld, _ := g.StreamData(li)
	h, err := DecodeLogicalHierarchyVersion(ld, g.FormatVersionEx(), true)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("GateHouse: objects=%d maxDepth=%d gaps=%d", h.Objects, h.MaxDepth, len(h.Gaps))
	for _, gg := range h.Gaps {
		t.Logf("gap pos=%d skipped=%d %s", gg.Pos, gg.Skipped, gg.Err)
	}
}
