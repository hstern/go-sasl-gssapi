# Contributing notes for agents and humans

- **Go 1.26+.** Runtime deps are kept minimal: `github.com/emersion/go-sasl` (the
  SASL client contract) and a Kerberos wire/crypto library (`gokrb5` family). No cgo.
- **Every `.go` file** starts with the two-line copyright + SPDX header:
  ```go
  // Copyright 2026 The go-sasl-gssapi Authors
  // SPDX-License-Identifier: Apache-2.0
  ```
- **Tests** are stdlib `testing` by default; a Kerberos library serves as the
  reference acceptor in integration tests.
- **Before a PR:** `go build ./... && go test ./... && golangci-lint run`.
- **Commits:** imperative mood, concise subject (`Add X`, `Fix Y`).
- **CI** must be green (`static`, `test`, `lint`) before merge.
