# tool

This command-line utility combines SSH usernames, passwords, and hosts into a list of credentials that can be consumed by other tooling.

## Usage

```bash
go run . \
  -users-file users.txt \
  -passwords-file passwords.txt \
  -hosts-file hosts.txt \
  [-port 22] \
  [-output good.txt] \
  [-workers $(nproc)]
```

### Flags

- `-users-file`: Path to a file containing SSH usernames (one per line).
- `-passwords-file`: Path to a file containing SSH passwords (one per line).
- `-hosts-file`: Path to a file containing SSH hosts (one per line, optional `:port`).
- `-port`: Default SSH server port used when host entries do not specify one. Defaults to `22`.
- `-output`: Path to the file where generated credentials will be saved. Defaults to `good.txt`.
- `-workers`: Number of concurrent workers used when processing hosts. Defaults to the number of CPU cores reported by the runtime. Values less than `1` are rejected.

All input files must contain at least one entry. Hosts may optionally specify a port using the `host:port` format; otherwise the default port is used.
