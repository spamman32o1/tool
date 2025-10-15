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
		user         = flag.String("user", "", "SSH username (required)")
		password     = flag.String("password", "", "SSH password (required unless -password-file is provided)")
		passwordFile = flag.String("password-file", "", "Path to a file containing the SSH password")
		host         = flag.String("host", "", "SSH server hostname or IP (required)")
		port         = flag.Int("port", 22, "SSH server port")
		output       = flag.String("output", "good.txt", "Path to the file where credentials will be saved")
	)

	flag.Parse()

	if *user == "" || *host == "" {
		flag.Usage()
		os.Exit(2)
	}

	pass := *password
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

	credential := fmt.Sprintf("%s|%d|%s|%s", *host, *port, *user, pass)
	if _, err := f.WriteString(credential); err != nil {
		log.Fatalf("failed to write credentials: %v", err)
	}
}
