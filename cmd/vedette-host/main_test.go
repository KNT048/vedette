package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		args    []string
		wantOut string
		wantErr bool
	}{
		{name: "version", args: []string{"-version"}, wantOut: "dev\n"},
		{name: "no server yet", args: nil, wantErr: true},
		{name: "unknown flag", args: []string{"-nope"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var out bytes.Buffer
			err := run(tt.args, &out)
			if (err != nil) != tt.wantErr {
				t.Fatalf("run(%q) error = %v, wantErr %v", tt.args, err, tt.wantErr)
			}
			if tt.wantOut != "" && out.String() != tt.wantOut {
				t.Fatalf("run(%q) output = %q, want %q", tt.args, out.String(), tt.wantOut)
			}
			if tt.wantErr && strings.Contains(out.String(), "dev\n") {
				t.Fatalf("run(%q) printed the version on error", tt.args)
			}
		})
	}
}
