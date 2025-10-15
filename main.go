package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
)

func main() {
	var (
		user            = flag.String("user", "", "SSH username (required unless -credentials-file is provided)")
		password        = flag.String("password", "", "SSH password (required unless -password-file is provided)")
		passwordFile    = flag.String("password-file", "", "Path to a file containing the SSH password")
		credentialsFile = flag.String("credentials-file", "", "Path to a file containing both the SSH username and password")
		host            = flag.String("host", "", "SSH server hostname or IP (required)")
		port            = flag.Int("port", 22, "SSH server port")
		output          = flag.String("output", "good.txt", "Path to the file where credentials will be saved")
	)

	flag.Parse()

	userVal := strings.TrimSpace(*user)
	pass := *password

	if *credentialsFile != "" {
		data, err := os.ReadFile(*credentialsFile)
		if err != nil {
			log.Fatalf("failed to read credentials file: %v", err)
		}

		cred := strings.TrimSpace(string(data))
		if cred == "" {
			log.Fatal("credentials file is empty")
		}

		switch {
		case strings.Contains(cred, "\n") || strings.Contains(cred, "\r"):
			fields := strings.FieldsFunc(cred, func(r rune) bool {
				return r == '\n' || r == '\r'
			})
			if len(fields) < 2 {
				log.Fatal("credentials file must contain both username and password")
			}
			userVal = strings.TrimSpace(fields[0])
			pass = strings.Join(fields[1:], "\n")
		case strings.Contains(cred, ":"):
			parts := strings.SplitN(cred, ":", 2)
			userVal = strings.TrimSpace(parts[0])
			pass = strings.TrimSpace(parts[1])
		default:
			log.Fatal("credentials file must be formatted as 'user:password' or on separate lines")
		}
	}

	if userVal == "" || *host == "" {
		flag.Usage()
		os.Exit(2)
	}

	if *passwordFile != "" {
		data, err := os.ReadFile(*passwordFile)
		if err != nil {
			log.Fatalf("failed to read password file: %v", err)
		}
		pass = string(data)
	}

	pass = strings.TrimRight(pass, "\r\n")

	if pass == "" {
		log.Fatal("no password provided (use -password or -password-file)")
	}

	f, err := os.OpenFile(*output, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		log.Fatalf("failed to open output file: %v", err)
	}
	defer f.Close()

	credential := fmt.Sprintf("%s|%d|%s|%s", *host, *port, userVal, pass)
	if _, err := f.WriteString(credential); err != nil {
		log.Fatalf("failed to write credentials: %v", err)
	}
}
