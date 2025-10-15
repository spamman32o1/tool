package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"golang.org/x/crypto/ssh"
)

func main() {
	var (
		user         = flag.String("user", "", "SSH username (required)")
		password     = flag.String("password", "", "SSH password (required unless -password-file is provided)")
		passwordFile = flag.String("password-file", "", "Path to a file containing the SSH password")
		host         = flag.String("host", "", "SSH server hostname or IP (required)")
		port         = flag.Int("port", 22, "SSH server port")
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

	if pass == "" {
		log.Fatal("no password provided (use -password or -password-file)")
	}

	config := &ssh.ClientConfig{
		User: *user,
		Auth: []ssh.AuthMethod{
			ssh.Password(pass),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	address := fmt.Sprintf("%s:%d", *host, *port)

	client, err := ssh.Dial("tcp", address, config)
	if err != nil {
		log.Fatalf("failed to connect to %s: %v", address, err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		log.Fatalf("failed to create session: %v", err)
	}
	defer session.Close()

	session.Stdin = os.Stdin
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}

	if err := session.RequestPty("xterm", 80, 40, modes); err != nil {
		log.Fatalf("failed to request PTY: %v", err)
	}

	if err := session.Shell(); err != nil {
		log.Fatalf("failed to start shell: %v", err)
	}

	if err := session.Wait(); err != nil {
		log.Fatalf("session ended with error: %v", err)
	}
}
