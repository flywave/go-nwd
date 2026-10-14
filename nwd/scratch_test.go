package nwd

import "testing"

func TestScratchWalkAPI(t *testing.T) {
	f := openReal(t)
	li := f.StreamByName("LcOpNwdLogicalHierarchy")
	ld, _ := f.StreamData(li)
	h, err := DecodeLogicalHierarchyVersion(ld, f.FormatVersionEx(), true)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("objects=%d maxDepth=%d gaps=%d", h.Objects, h.MaxDepth, len(h.Gaps))
	for _, g := range h.Gaps {
		t.Logf("gap pos=%d skipped=%d %s", g.Pos, g.Skipped, g.Err)
	}
}

func TestScratchDumpRegion(t *testing.T) {
	f := openReal(t)
	li := f.StreamByName("LcOpNwdLogicalHierarchy")
	ld, _ := f.StreamData(li)
	for _, r := range [][2]int{{58240, 58340}, {61850, 61920}} {
		for off := r[0]; off < r[1]; off += 16 {
			t.Logf("hex %5d: % x", off, ld[off:off+16])
		}
		t.Logf("---")
	}
}
