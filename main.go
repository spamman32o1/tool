package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

func main() {
	var (
		usersFile     = flag.String("users-file", "", "Path to a file containing SSH usernames (one per line)")
		passwordsFile = flag.String("passwords-file", "", "Path to a file containing SSH passwords (one per line)")
		hostsFile     = flag.String("hosts-file", "", "Path to a file containing SSH hosts (one per line, optional :port)")
		port          = flag.Int("port", 22, "SSH server port")
		output        = flag.String("output", "good.txt", "Path to the file where credentials will be saved")
		workers       = flag.Int("workers", runtime.NumCPU(), "Number of concurrent workers to use when processing hosts")
		probeTimeout  = flag.Duration("probe-timeout", 0, "Timeout used when probing hosts before queuing them (0 to disable)")
	)

	flag.Parse()

	if *workers < 1 {
		fmt.Fprintln(os.Stderr, "workers must be at least 1")
		flag.Usage()
		os.Exit(2)
	}

	cfg := processingConfig{
		port:         *port,
		workers:      *workers,
		output:       *output,
		probeTimeout: *probeTimeout,
	}

	hosts, err := loadHosts(*hostsFile)
	if err != nil {
		log.Fatal(err)
	}

	credentials, err := gatherCredentials(*usersFile, *passwordsFile)
	if err != nil {
		log.Fatal(err)
	}

	if len(hosts) == 0 {
		flag.Usage()
		os.Exit(2)
	}

	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(credentials), func(i, j int) {
		credentials[i], credentials[j] = credentials[j], credentials[i]
	})

	f, err := os.OpenFile(cfg.output, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		log.Fatalf("failed to open output file: %v", err)
	}
	defer f.Close()

	writer := bufio.NewWriterSize(f, cfg.workers*1024)
	defer func() {
		if err := writer.Flush(); err != nil {
			log.Fatalf("failed to flush output: %v", err)
		}
	}()

	if err := processHosts(cfg, hosts, credentials, writer); err != nil {
		log.Fatal(err)
	}
}

type dialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

type processingConfig struct {
	port         int
	workers      int
	output       string
	probeTimeout time.Duration
	dialContext  dialContextFunc
}

type credential struct {
	user     string
	password string
}

type hostTarget struct {
	host string
	port int
}

type credentialJob struct {
	target     hostTarget
	credential credential
}

func processHosts(cfg processingConfig, hosts []string, credentials []credential, output io.Writer) error {
	parsedHosts := make([]hostTarget, 0, len(hosts))
	seenTargets := make(map[string]struct{})
	for _, hostEntry := range hosts {
		hostEntry = strings.TrimSpace(hostEntry)
		if hostEntry == "" {
			continue
		}

		currentHost := hostEntry
		currentPort := cfg.port

		if strings.Contains(hostEntry, ":") {
			h, p, err := net.SplitHostPort(hostEntry)
			if err != nil {
				return fmt.Errorf("invalid host entry %q: %w", hostEntry, err)
			}

			portNum, err := strconv.Atoi(p)
			if err != nil {
				return fmt.Errorf("invalid port in host entry %q: %w", hostEntry, err)
			}

			currentHost = h
			currentPort = portNum
		}

		targets, err := expandHostTargets(currentHost, currentPort)
		if err != nil {
			return err
		}

		for _, target := range targets {
			key := makeTargetKey(target)
			if _, exists := seenTargets[key]; exists {
				continue
			}
			responsive, err := cfg.probeTarget(target)
			if err != nil {
				return err
			}
			if !responsive {
				continue
			}
			seenTargets[key] = struct{}{}
			parsedHosts = append(parsedHosts, target)
		}
	}

	if len(parsedHosts) == 0 {
		return fmt.Errorf("no valid hosts provided after resolution and probing")
	}

	jobBuffer := cfg.workers * 4
	if jobBuffer < 1 {
		jobBuffer = 1
	}

	jobs := make(chan credentialJob, jobBuffer)
	lines := make(chan string, jobBuffer)

	var workersWG sync.WaitGroup
	for i := 0; i < cfg.workers; i++ {
		workersWG.Add(1)
		go func() {
			defer workersWG.Done()
			for job := range jobs {
				line := fmt.Sprintf("%s|%d|%s|%s", job.target.host, job.target.port, job.credential.user, job.credential.password)
				lines <- line
			}
		}()
	}

	errCh := make(chan error, 1)
	go func() {
		var writeErr error
		for line := range lines {
			if writeErr != nil {
				continue
			}
			if _, err := fmt.Fprintln(output, line); err != nil {
				writeErr = fmt.Errorf("failed to write credentials: %w", err)
			}
		}
		errCh <- writeErr
	}()

	for _, host := range parsedHosts {
		for _, cred := range credentials {
			jobs <- credentialJob{target: host, credential: cred}
		}
	}

	close(jobs)
	workersWG.Wait()
	close(lines)

	if err := <-errCh; err != nil {
		return err
	}

	return nil
}

func expandHostTargets(host string, port int) ([]hostTarget, error) {
	targets := []hostTarget{{host: host, port: port}}
	if ip := net.ParseIP(host); ip != nil {
		return targets, nil
	}

	resolved, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve host %q: %w", host, err)
	}

	for _, ip := range resolved {
		targets = append(targets, hostTarget{host: ip.String(), port: port})
	}

	return targets, nil
}

func makeTargetKey(target hostTarget) string {
	return fmt.Sprintf("%s|%d", target.host, target.port)
}

func (cfg processingConfig) shouldProbe() bool {
	return cfg.probeTimeout > 0 || cfg.dialContext != nil
}

func (cfg processingConfig) probeTarget(target hostTarget) (bool, error) {
	if !cfg.shouldProbe() {
		return true, nil
	}

	address := net.JoinHostPort(target.host, strconv.Itoa(target.port))

	var (
		ctx    = context.Background()
		cancel context.CancelFunc
	)

	if cfg.probeTimeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, cfg.probeTimeout)
		defer cancel()
	}

	dialer := cfg.dialContext
	if dialer == nil {
		d := &net.Dialer{Timeout: cfg.probeTimeout}
		dialer = d.DialContext
	}

	conn, err := dialer(ctx, "tcp", address)
	if err != nil {
		return false, nil
	}
	defer conn.Close()

	return true, nil
}

func loadHosts(hostsFile string) ([]string, error) {
	if strings.TrimSpace(hostsFile) == "" {
		return nil, fmt.Errorf("hosts file is required")
	}

	file, err := os.Open(hostsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read hosts file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var hosts []string
	for scanner.Scan() {
		line := strings.TrimSpace(strings.TrimRight(scanner.Text(), "\r"))
		if line != "" {
			hosts = append(hosts, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read hosts file: %w", err)
	}

	if len(hosts) == 0 {
		return nil, fmt.Errorf("hosts file is empty")
	}

	return hosts, nil
}

func gatherCredentials(usersFile, passwordsFile string) ([]credential, error) {
	var credentials []credential

	usersFile = strings.TrimSpace(usersFile)
	passwordsFile = strings.TrimSpace(passwordsFile)

	if usersFile == "" || passwordsFile == "" {
		return nil, fmt.Errorf("both users-file and passwords-file must be provided")
	}

	users, err := loadEntries(usersFile, false)
	if err != nil {
		return nil, fmt.Errorf("failed to read users file: %w", err)
	}

	passwords, err := loadEntries(passwordsFile, true)
	if err != nil {
		return nil, fmt.Errorf("failed to read passwords file: %w", err)
	}

	if len(users) == 0 {
		return nil, fmt.Errorf("users file is empty")
	}

	if len(passwords) == 0 {
		return nil, fmt.Errorf("passwords file is empty")
	}

	for _, user := range users {
		for _, password := range passwords {
			credentials = append(credentials, credential{user: user, password: password})
		}
	}

	return credentials, nil
}

func loadEntries(path string, preserveSpaces bool) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var entries []string
	for scanner.Scan() {
		raw := strings.TrimRight(scanner.Text(), "\r")
		if strings.TrimSpace(raw) == "" {
			continue
		}
		if preserveSpaces {
			entries = append(entries, raw)
		} else {
			entries = append(entries, strings.TrimSpace(raw))
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return entries, nil
}
