package nwd

import "testing"

// Synthetic check of the marker-based name scanner.
func TestScanNamesSynthetic(t *testing.T) {
	w := NewObjectWriter()
	w.Name("Location", "LcRevitPropertyLocation") // slot 0
	w.Name("Latitude", "revit_Latitude")         // slot 1
	w.End()
	names := ScanNames(w.Bytes(), 10)
	if len(names) != 2 {
		t.Fatalf("names=%d want 2", len(names))
	}
	if names[0].Name != "LcRevitPropertyLocation" || names[1].Name != "revit_Latitude" {
		t.Errorf("names=%+v", names)
	}

	kinds := ScanObjectKinds(w.Bytes(), 10)
	if len(kinds) != 2 || kinds[0].TypeID != TypeName {
		t.Errorf("kinds=%+v", kinds)
	}
}
