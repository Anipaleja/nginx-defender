package main

import (
	"testing"
)

func TestBasic(t *testing.T) {
	// Basic test to ensure the build system works
	if 1+1 != 2 {
		t.Error("Basic math failed")
	}
}

func TestVersion(t *testing.T) {
	// Test that we can at least compile
	version := "2.0.0"
	if version == "" {
		t.Error("Version should not be empty")
	}
}
