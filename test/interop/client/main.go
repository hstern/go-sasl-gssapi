// Copyright 2026 The go-sasl-gssapi Authors
// SPDX-License-Identifier: Apache-2.0

// Command interop-client drives the go-sasl-gssapi client for the interop
// harness. It loads the ccache named by $KRB5CCNAME, runs the SASL GSSAPI
// exchange for the SPN in argv[1] (optional authzid in argv[2]), and speaks a
// line protocol over stdin/stdout: it prints the base64 initial response, then
// for each base64 server challenge read on stdin it prints the base64 response
// (an empty line for an empty token). The acceptor side is accept.py, driven by
// MIT krb5 via python-gssapi.
package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/hstern/krb5/credentials"

	saslgssapi "github.com/hstern/go-sasl-gssapi"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "interop-client:", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 {
		return fmt.Errorf("usage: interop-client <spn> [authzid]")
	}
	spn := os.Args[1]
	authzid := ""
	if len(os.Args) > 2 {
		authzid = os.Args[2]
	}

	ccPath := strings.TrimPrefix(os.Getenv("KRB5CCNAME"), "FILE:")
	if ccPath == "" {
		return fmt.Errorf("KRB5CCNAME is not set")
	}
	cc, err := credentials.LoadCCache(ccPath)
	if err != nil {
		return fmt.Errorf("load ccache %q: %w", ccPath, err)
	}

	krbClient, err := saslgssapi.FromCCache(cc)
	if err != nil {
		return fmt.Errorf("FromCCache: %w", err)
	}
	client, err := saslgssapi.NewClient(saslgssapi.Config{Client: krbClient, Service: spn, AuthzID: authzid})
	if err != nil {
		return fmt.Errorf("NewClient: %w", err)
	}

	out := bufio.NewWriter(os.Stdout)
	emit := func(b []byte) error {
		if _, err := fmt.Fprintln(out, base64.StdEncoding.EncodeToString(b)); err != nil {
			return err
		}
		return out.Flush()
	}

	_, ir, err := client.Start()
	if err != nil {
		return fmt.Errorf("client start: %w", err)
	}
	if err := emit(ir); err != nil {
		return err
	}

	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for in.Scan() {
		line := strings.TrimSpace(in.Text())
		var challenge []byte
		if line != "" {
			if challenge, err = base64.StdEncoding.DecodeString(line); err != nil {
				return fmt.Errorf("decode challenge: %w", err)
			}
		}
		resp, err := client.Next(challenge)
		if err != nil {
			return fmt.Errorf("client next: %w", err)
		}
		if err := emit(resp); err != nil {
			return err
		}
	}
	return in.Err()
}
