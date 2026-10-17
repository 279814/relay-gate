package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestExplicitPublicIPConfirmationPrecedesSideEffects(t *testing.T) {
	for _, args := range [][]string{
		{"--ip", "8.8.8.8"},
		{"--ip", "8.8.8.8", "--confirmed-ip", "9.9.9.9"},
		{"--ip", "127.0.0.1", "--confirmed-ip", "127.0.0.1"},
	} {
		var output bytes.Buffer
		if err := run(args, &output, &output); err == nil {
			t.Fatalf("accepted unsafe invocation: %v", args)
		}
	}
}

func TestPublicIPCheckDoesNotStartACME(t *testing.T) {
	var output bytes.Buffer
	if err := run([]string{"--check-ip", "--ip", "2001:4860:0:0:0:0:0:8888"}, &output, &output); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(output.String()) != "2001:4860::8888" {
		t.Fatalf("unexpected canonical IP: %q", output.String())
	}
}
