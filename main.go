package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
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
	)

	flag.Parse()

	if *workers < 1 {
		fmt.Fprintln(os.Stderr, "workers must be at least 1")
		flag.Usage()
		os.Exit(2)
	}

	cfg := processingConfig{
		port:    *port,
		workers: *workers,
		output:  *output,
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

	for _, hostEntry := range hosts {
		hostEntry = strings.TrimSpace(hostEntry)
		if hostEntry == "" {
			continue
		}

		currentHost := hostEntry
		currentPort := cfg.port

		if strings.Contains(hostEntry, ":") {
			if h, p, err := net.SplitHostPort(hostEntry); err == nil {
				currentHost = h
				portNum, err := strconv.Atoi(p)
				if err != nil {
					log.Fatalf("invalid port in host entry %q: %v", hostEntry, err)
				}
				currentPort = portNum
			}
		}

		for _, credential := range credentials {
			line := fmt.Sprintf("%s|%d|%s|%s", currentHost, currentPort, credential.user, credential.password)
			if _, err := fmt.Fprintln(writer, line); err != nil {
				log.Fatalf("failed to write credentials: %v", err)
			}
		}
	}
}

type processingConfig struct {
	port    int
	workers int
	output  string
}

type credential struct {
	user     string
	password string
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
