// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package session

import "time"

// DefaultConfig returns a SessionConfig with sensible defaults.
func DefaultConfig() SessionConfig {
	return SessionConfig{
		IdleTimeout:     30 * time.Minute,
		AbsoluteTimeout: 24 * time.Hour,
		MaxConcurrent:   5,
		CookieName:      "auth_session",
		CookieDomain:    "",
		CookieSecure:    true,
		CookieSameSite:  "Strict",
	}
}
