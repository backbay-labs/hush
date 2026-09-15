package hushspec

// Pointer helpers for the optional fields of the model. Several of the model's
// fields are pointers because presence is load-bearing, so a table-driven test
// needs a one-expression way to spell "present, and this value".

func strPtr(s string) *string                   { return &s }
func intPtr(i int) *int                         { return &i }
func boolPtr(b bool) *bool                      { return &b }
func floatPtr(f float64) *float64               { return &f }
func levelPtr(l DetectionLevel) *DetectionLevel { return &l }
