package cli

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			code := Run(tt.args, &stdout, &stderr)
			require.Equal(t, tt.code, code, "exit code")

			if tt.out == "" {
				assert.Empty(t, stdout.String(), "unexpected stdout")
			} else {
				assert.Contains(t, stdout.String(), tt.out, "stdout")
			}
			if tt.err == "" {
				assert.Empty(t, stderr.String(), "unexpected stderr")
			} else {
				assert.Contains(t, stderr.String(), tt.err, "stderr")
			}
		})
	}
}

func TestRunRootHelpAndVersionOutput(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "default help", want: help},
		{name: "help command", args: []string{"help"}, want: help},
		{name: "short help", args: []string{"-h"}, want: help},
		{name: "long help", args: []string{"--help"}, want: help},
		{name: "version command", args: []string{"version"}, want: "dottie dev (scaffold)\n"},
		{name: "version flag", args: []string{"--version"}, want: "dottie dev (scaffold)\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			require.Equal(t, 0, Run(tt.args, &stdout, &stderr), "exit code")
			assert.Equal(t, tt.want, stdout.String(), "stdout")
			assert.Empty(t, stderr.String(), "stderr")
		})
	}
}

func TestRunDispatchesTargetsCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	require.Equal(t, 2, Run([]string{"targets"}, &stdout, &stderr), "exit code")
	assert.Empty(t, stdout.String(), "unexpected stdout")
	assert.Equal(t, "dottie: usage: expected list, add, remove or mode\n", stderr.String(), "targets dispatch error")
}

func TestRunQuotesUntrustedArguments(t *testing.T) {
	var stdout, stderr bytes.Buffer
	argument := "\x1b[2J\n"
	require.Equal(t, 2, Run([]string{argument}, &stdout, &stderr), "exit code")
	assert.Equal(t, "dottie: unsupported command "+fmt.Sprintf("%q", argument)+"; run 'dottie help'\n", stderr.String(), "unsupported command output")
	assert.NotContains(t, stderr.String(), "\x1b", "unescaped terminal controls")
	assert.Equal(t, 1, strings.Count(stderr.String(), "\n"), "unescaped terminal controls")
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("output unavailable")
}

func TestRunOutputFailure(t *testing.T) {
	for _, args := range [][]string{nil, {"help"}, {"--help"}, {"version"}, {"--version"}} {
		var stderr bytes.Buffer
		require.Equal(t, 1, Run(args, failingWriter{}, &stderr), "exit code")
		assert.Contains(t, stderr.String(), "cannot write command output", "missing output error")
	}
}
