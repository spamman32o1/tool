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
	cfg.authenticator = func(ctx context.Context, target hostTarget, cred credential) (bool, error) {
		return true, nil
	}
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
	cfg.authenticator = func(ctx context.Context, target hostTarget, cred credential) (bool, error) {
		return true, nil
	}
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
	cfg.authenticator = func(ctx context.Context, target hostTarget, cred credential) (bool, error) {
		return true, nil
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

func TestProcessHostsUsesFallbackPorts(t *testing.T) {
	cfg := processingConfig{port: 22, workers: 1, probeTimeout: 5 * time.Millisecond}
	cfg.authenticator = func(ctx context.Context, target hostTarget, cred credential) (bool, error) {
		return true, nil
	}

	var attempts []string
	cfg.dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		attempts = append(attempts, address)
		switch {
		case strings.HasSuffix(address, ":22"), strings.HasSuffix(address, ":2222"):
			return nil, fmt.Errorf("closed: %s", address)
		case strings.HasSuffix(address, ":2200"):
			client, server := net.Pipe()
			server.Close()
			return client, nil
		default:
			return nil, fmt.Errorf("closed: %s", address)
		}
	}

	hosts := []string{"192.0.2.10"}
	credentials := []credential{{user: "fallback", password: "check"}}

	var buf bytes.Buffer
	writer := bufio.NewWriter(&buf)

	if err := processHosts(cfg, hosts, credentials, writer); err != nil {
		t.Fatalf("processHosts returned unexpected error: %v", err)
	}

	if err := writer.Flush(); err != nil {
		t.Fatalf("failed to flush writer: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected exactly one credential line, got %d: %v", len(lines), lines)
	}

	expectedLine := "192.0.2.10|2200|fallback|check"
	if lines[0] != expectedLine {
		t.Fatalf("unexpected credential line: %q", lines[0])
	}

	expectedAttempts := []string{"192.0.2.10:22", "192.0.2.10:2222", "192.0.2.10:2200"}
	if len(attempts) < len(expectedAttempts) {
		t.Fatalf("expected at least attempts %v, got %v", expectedAttempts, attempts)
	}

	for i, attempt := range expectedAttempts {
		if attempts[i] != attempt {
			t.Fatalf("unexpected probe order at position %d: got %s want %s", i, attempts[i], attempt)
		}
	}

	if last := attempts[len(attempts)-1]; last != "192.0.2.10:2200" {
		t.Fatalf("expected final probe against chosen port, got %s", last)
	}
}

func TestProcessHostsFiltersByAuthentication(t *testing.T) {
	cfg := processingConfig{port: 2222, workers: 2}

	cfg.authenticator = func(ctx context.Context, target hostTarget, cred credential) (bool, error) {
		return cred.password == "wonder", nil
	}

	hosts := []string{"192.0.2.20:2222"}
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

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")

	expected := []string{"192.0.2.20|2222|alice|wonder"}
	if len(lines) != len(expected) {
		t.Fatalf("expected %d authenticated credentials, got %d: %v", len(expected), len(lines), lines)
	}

	if lines[0] != expected[0] {
		t.Fatalf("unexpected credential line: %q", lines[0])
	}
}

func TestProcessHostsAuthenticationError(t *testing.T) {
	cfg := processingConfig{port: 22, workers: 1}

	expectedErr := fmt.Errorf("authenticator failed")
	cfg.authenticator = func(ctx context.Context, target hostTarget, cred credential) (bool, error) {
		return false, expectedErr
	}

	hosts := []string{"192.0.2.30:22"}
	credentials := []credential{{user: "user", password: "pass"}}

	var buf bytes.Buffer
	writer := bufio.NewWriter(&buf)

	err := processHosts(cfg, hosts, credentials, writer)
	if err == nil {
		t.Fatal("expected authenticator error, got nil")
	}

	if !strings.Contains(err.Error(), expectedErr.Error()) {
		t.Fatalf("unexpected authenticator error: %v", err)
	}
}
