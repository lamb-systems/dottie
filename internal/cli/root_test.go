package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	tests := []struct {
		name string
		args []string
		code int
		out  string
		err  string
	}{
		{name: "default help", code: 0, out: "This is a scaffold"},
		{name: "help", args: []string{"help"}, code: 0, out: "See README.md for build instructions and current status."},
		{name: "help flag", args: []string{"--help"}, code: 0, out: "Usage:"},
		{name: "short help", args: []string{"-h"}, code: 0, out: "Usage:"},
		{name: "version", args: []string{"version"}, code: 0, out: "dottie dev (scaffold)"},
		{name: "version flag", args: []string{"--version"}, code: 0, out: "dottie dev (scaffold)"},
		{name: "unimplemented sync", args: []string{"sync"}, code: 2, err: "unsupported command"},
		{name: "unimplemented daemon", args: []string{"serve"}, code: 2, err: "unsupported command"},
		{name: "unimplemented login", args: []string{"login"}, code: 2, err: "unsupported command"},
		{name: "unknown", args: []string{"unknown"}, code: 2, err: "unsupported command"},
		{name: "unexpected arguments", args: []string{"version", "extra"}, code: 2, err: "expected one command"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := Run(tt.args, &stdout, &stderr); code != tt.code {
				t.Fatalf("exit code = %d, want %d", code, tt.code)
			}
			if tt.out == "" && stdout.Len() != 0 {
				t.Fatalf("unexpected stdout: %q", stdout.String())
			}
			if tt.out != "" && !strings.Contains(stdout.String(), tt.out) {
				t.Errorf("stdout = %q, want substring %q", stdout.String(), tt.out)
			}
			if tt.err == "" && stderr.Len() != 0 {
				t.Fatalf("unexpected stderr: %q", stderr.String())
			}
			if tt.err != "" && !strings.Contains(stderr.String(), tt.err) {
				t.Errorf("stderr = %q, want substring %q", stderr.String(), tt.err)
			}
		})
	}
}

func TestRunDispatchesTargetsCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"targets"}, &stdout, &stderr); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "expected list, add, remove or mode") {
		t.Fatalf("targets dispatch output = %q, error = %q", stdout.String(), stderr.String())
	}
}

func TestRunQuotesUntrustedArguments(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"\x1b[2J\n"}, &stdout, &stderr); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if strings.ContainsRune(stderr.String(), '\x1b') || strings.Count(stderr.String(), "\n") != 1 {
		t.Fatalf("unescaped terminal controls: %q", stderr.String())
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("output unavailable")
}

func TestRunOutputFailure(t *testing.T) {
	for _, args := range [][]string{nil, {"version"}} {
		var stderr bytes.Buffer
		if code := Run(args, failingWriter{}, &stderr); code != 1 {
			t.Fatalf("exit code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "cannot write command output") {
			t.Fatalf("missing output error: %q", stderr.String())
		}
	}
}
