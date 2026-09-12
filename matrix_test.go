package main

import "testing"

func TestSetActiveMatrix(t *testing.T) {
	if err := setActiveMatrix("mobile"); err != nil {
		t.Fatalf("setActiveMatrix(mobile) returned error: %v", err)
	}
	if activeMatrixName() != "mobile" {
		t.Fatalf("activeMatrixName() = %q, want mobile", activeMatrixName())
	}
	if cachePath != mobileMatrix.CachePath {
		t.Fatalf("cachePath = %q, want %q", cachePath, mobileMatrix.CachePath)
	}

	if err := setActiveMatrix("enterprise"); err != nil {
		t.Fatalf("setActiveMatrix(enterprise) returned error: %v", err)
	}
}

func TestSetActiveMatrixRejectsUnknown(t *testing.T) {
	if err := setActiveMatrix("unknown"); err == nil {
		t.Fatal("expected unsupported matrix error")
	}
}
