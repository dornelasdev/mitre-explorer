package main

import "testing"

func TestVersionIsSet(t *testing.T) {
	if version == "" {
		t.Fatal("version should not be empty")
	}
}
