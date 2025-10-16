package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestProcessHostsGeneratesAllLines(t *testing.T) {
	cfg := processingConfig{port: 22, workers: 3}
	hosts := []string{"203.0.113.10", "10.0.0.1:2200", "   198.51.100.5  "}
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
		"203.0.113.10|22|alice|wonder": {},
		"203.0.113.10|22|bob|builder":  {},
		"10.0.0.1|2200|alice|wonder":   {},
		"10.0.0.1|2200|bob|builder":    {},
		"198.51.100.5|22|alice|wonder": {},
		"198.51.100.5|22|bob|builder":  {},
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

func TestProcessHostsResolvesDomain(t *testing.T) {
	cfg := processingConfig{port: 22, workers: 2}
	hosts := []string{"localhost", " localhost "}
	credentials := []credential{{user: "user", password: "pass"}}

	var buf bytes.Buffer
	writer := bufio.NewWriter(&buf)

	if err := processHosts(cfg, hosts, credentials, writer); err != nil {
		t.Fatalf("processHosts returned unexpected error: %v", err)
	}

	if err := writer.Flush(); err != nil {
		t.Fatalf("failed to flush writer: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) == 0 {
		t.Fatal("expected at least one credential line")
	}

	expected := map[string]struct{}{
		"localhost|22|user|pass": {},
	}

	ips, err := net.LookupIP("localhost")
	if err != nil {
		t.Fatalf("failed to lookup localhost: %v", err)
	}

	for _, ip := range ips {
		expected[fmt.Sprintf("%s|22|user|pass", ip.String())] = struct{}{}
	}

	if len(lines) != len(expected) {
		t.Fatalf("expected %d credential lines, got %d: %v", len(expected), len(lines), lines)
	}

	for _, line := range lines {
		if _, ok := expected[line]; !ok {
			t.Fatalf("unexpected credential line: %q", line)
		}
		delete(expected, line)
	}

	if len(expected) != 0 {
		t.Fatalf("missing expected credentials: %v", expected)
	}
}

func TestProcessHostsProbingSkipsUnresponsive(t *testing.T) {
	cfg := processingConfig{
		port:         2200,
		workers:      1,
		probeTimeout: 5 * time.Millisecond,
	}

	cfg.dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		switch {
		case strings.Contains(address, "localhost"), strings.Contains(address, "127.0.0.1"), strings.Contains(address, "[::1]"):
			client, server := net.Pipe()
			server.Close()
			return client, nil
		default:
			return nil, fmt.Errorf("dial failed for %s", address)
		}
	}

	hosts := []string{"localhost", "192.0.2.123"}
	credentials := []credential{{user: "probe", password: "check"}}

	var buf bytes.Buffer
	writer := bufio.NewWriter(&buf)

	if err := processHosts(cfg, hosts, credentials, writer); err != nil {
		t.Fatalf("processHosts returned unexpected error: %v", err)
	}

	if err := writer.Flush(); err != nil {
		t.Fatalf("failed to flush writer: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) == 0 {
		t.Fatal("expected responsive hosts to be queued")
	}

	expected := map[string]struct{}{
		"localhost|2200|probe|check": {},
	}

	ips, err := net.LookupIP("localhost")
	if err != nil {
		t.Fatalf("failed to lookup localhost: %v", err)
	}

	for _, ip := range ips {
		expected[fmt.Sprintf("%s|2200|probe|check", ip.String())] = struct{}{}
	}

	if len(lines) != len(expected) {
		t.Fatalf("expected %d responsive host credential lines, got %d: %v", len(expected), len(lines), lines)
	}

	for _, line := range lines {
		if _, ok := expected[line]; !ok {
			t.Fatalf("unexpected line (possibly from unresponsive host): %q", line)
		}
		delete(expected, line)
	}

	if len(expected) != 0 {
		t.Fatalf("missing expected responsive host credentials: %v", expected)
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
