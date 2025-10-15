package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	var (
		usersFile       = flag.String("users-file", "", "Path to a file containing SSH usernames (one per line)")
		passwordsFile   = flag.String("passwords-file", "", "Path to a file containing SSH passwords (one per line)")
		credentialsFile = flag.String("credentials-file", "", "Path to a file containing SSH username/password pairs")
		hostsFile       = flag.String("hosts-file", "", "Path to a file containing SSH hosts (one per line, optional :port)")
		port            = flag.Int("port", 22, "SSH server port")
		output          = flag.String("output", "good.txt", "Path to the file where credentials will be saved")
	)

	flag.Parse()

	hosts, err := loadHosts(*hostsFile)
	if err != nil {
		log.Fatal(err)
	}

	credentials, err := gatherCredentials(*credentialsFile, *usersFile, *passwordsFile)
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

	f, err := os.OpenFile(*output, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		log.Fatalf("failed to open output file: %v", err)
	}
	defer f.Close()

	for _, hostEntry := range hosts {
		hostEntry = strings.TrimSpace(hostEntry)
		if hostEntry == "" {
			continue
		}

		currentHost := hostEntry
		currentPort := *port

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
			if _, err := fmt.Fprintln(f, line); err != nil {
				log.Fatalf("failed to write credentials: %v", err)
			}
		}
	}
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

func gatherCredentials(credentialsFile, usersFile, passwordsFile string) ([]credential, error) {
	var credentials []credential

	if strings.TrimSpace(credentialsFile) != "" {
		fileCreds, err := loadCredentialPairs(credentialsFile)
		if err != nil {
			return nil, err
		}
		credentials = append(credentials, fileCreds...)
	}

	usersFile = strings.TrimSpace(usersFile)
	passwordsFile = strings.TrimSpace(passwordsFile)

	if usersFile != "" || passwordsFile != "" {
		if usersFile == "" || passwordsFile == "" {
			return nil, fmt.Errorf("both users-file and passwords-file must be provided together")
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
	}

	if len(credentials) == 0 {
		return nil, fmt.Errorf("no credentials provided")
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

func loadCredentialPairs(path string) ([]credential, error) {
	entries, err := loadEntries(path, true)
	if err != nil {
		return nil, fmt.Errorf("failed to read credentials file: %w", err)
	}

	if len(entries) == 0 {
		return nil, fmt.Errorf("credentials file is empty")
	}

	var credentials []credential
	for _, entry := range entries {
		trimmed := strings.TrimSpace(entry)
		if trimmed == "" {
			continue
		}

		var user, password string
		if strings.Contains(trimmed, ":") {
			parts := strings.SplitN(trimmed, ":", 2)
			user = strings.TrimSpace(parts[0])
			password = strings.TrimSpace(parts[1])
		} else {
			fields := strings.Fields(trimmed)
			if len(fields) < 2 {
				return nil, fmt.Errorf("credentials file must contain entries formatted as 'user:password' or 'user password'")
			}
			user = fields[0]
			password = strings.Join(fields[1:], " ")
		}

		if user == "" {
			return nil, fmt.Errorf("credentials file entry missing username")
		}

		credentials = append(credentials, credential{user: user, password: password})
	}

	if len(credentials) == 0 {
		return nil, fmt.Errorf("credentials file is empty")
	}

	return credentials, nil
}
