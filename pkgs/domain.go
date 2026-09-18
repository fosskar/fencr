package main

import "strings"

// the one wildcard rule, built into both the egress unit and the command:
// `*.example.com` covers the names below example.com, not example.com itself
func covers(pattern, host string) bool {
	host = strings.ToLower(host)
	pattern = strings.ToLower(pattern)
	if suffix, wildcard := strings.CutPrefix(pattern, "*."); wildcard {
		return strings.HasSuffix(host, "."+suffix)
	}
	return host == pattern
}
