// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package password

import (
	"bufio"
	"crypto/sha1"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// HIBPChecker checks passwords against the HaveIBeenPwned API using
// k-anonymity. Only the first 5 characters of the SHA-1 hash are sent
// to the API — the full password never leaves the library.
type HIBPChecker struct {
	// Client is the HTTP client used for API calls.
	// A custom client can be provided for timeout control.
	Client *http.Client

	// APIURL is the base URL for the HIBP Pwned Passwords API.
	// Defaults to "https://api.pwnedpasswords.com/range/".
	APIURL string
}

// NewHIBPChecker creates a new HIBPChecker with sensible defaults.
func NewHIBPChecker() *HIBPChecker {
	return &HIBPChecker{
		Client: &http.Client{
			Timeout: 5 * time.Second,
		},
		APIURL: "https://api.pwnedpasswords.com/range/",
	}
}

// IsBreached checks if the password has appeared in a known data breach.
// Uses SHA-1 k-anonymity: only the first 5 characters of the SHA-1 hash
// are sent to the API.
func (c *HIBPChecker) IsBreached(password string) (bool, error) {
	hash := sha1Hash(password)
	prefix := strings.ToUpper(hash[:5])
	suffix := strings.ToUpper(hash[5:])

	url := c.apiURL() + prefix
	resp, err := c.Client.Get(url)
	if err != nil {
		return false, fmt.Errorf("auth/password: HIBP API request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("auth/password: HIBP API returned status %d", resp.StatusCode)
	}

	return containsSuffix(resp.Body, suffix)
}

// SHA1Prefix returns the first 5 characters of the SHA-1 hash of the password.
// Exported for testing k-anonymity compliance.
func SHA1Prefix(password string) string {
	hash := sha1Hash(password)
	return strings.ToUpper(hash[:5])
}

func (c *HIBPChecker) apiURL() string {
	if c.APIURL != "" {
		return c.APIURL
	}
	return "https://api.pwnedpasswords.com/range/"
}

func sha1Hash(s string) string {
	h := sha1.New()
	h.Write([]byte(s))
	return fmt.Sprintf("%X", h.Sum(nil))
}

func containsSuffix(r io.Reader, suffix string) (bool, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 2)
		if len(parts) >= 1 && strings.EqualFold(parts[0], suffix) {
			if len(parts) == 2 {
				count, _ := strconv.Atoi(strings.TrimSpace(parts[1]))
				if count > 0 {
					return true, nil
				}
			}
			return true, nil
		}
	}
	return false, scanner.Err()
}
