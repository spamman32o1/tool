package main

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

func TestProcessHostsGeneratesAllLines(t *testing.T) {
	cfg := processingConfig{port: 22, workers: 3}
	hosts := []string{"example.com", "10.0.0.1:2200", "   host.local  "}
	credentials := []credential{
		{user: "alice", password: "wonder"},
		{user: "bob", password: "builder"},
	}

	var buf bytes.Buffer
	writer := bufio.NewWriter(&buf)

	if err := processHosts(cfg, hosts, credentials, writer); err != nil {
		t.Fatalf("processHosts returned unexpected error: %v", err)
	}

	if err := writer.Flush(); err != nil {
		t.Fatalf("failed to flush writer: %v", err)
	}

	output := strings.TrimSpace(buf.String())
	if output == "" {
		t.Fatal("no credentials were written")
	}

	lines := strings.Split(output, "\n")
	expected := map[string]struct{}{
		"example.com|22|alice|wonder": {},
		"example.com|22|bob|builder":  {},
		"10.0.0.1|2200|alice|wonder":  {},
		"10.0.0.1|2200|bob|builder":   {},
		"host.local|22|alice|wonder":  {},
		"host.local|22|bob|builder":   {},
	}

	if len(lines) != len(expected) {
		t.Fatalf("expected %d lines, got %d: %v", len(expected), len(lines), lines)
	}

	for _, line := range lines {
		if _, ok := expected[line]; !ok {
			t.Fatalf("unexpected line in output: %q", line)
		}
		delete(expected, line)
	}

	if len(expected) != 0 {
		t.Fatalf("missing expected lines: %v", expected)
	}
}

func TestProcessHostsInvalidHost(t *testing.T) {
	cfg := processingConfig{port: 22, workers: 2}
	hosts := []string{"invalid:port"}
	credentials := []credential{{user: "user", password: "pass"}}

	var buf bytes.Buffer
	writer := bufio.NewWriter(&buf)

	if err := processHosts(cfg, hosts, credentials, writer); err == nil {
		t.Fatal("expected error for invalid host entry, got nil")
	}
}
