package main

import (
	"strings"
	"testing"
)

func TestReorderHeadlessArgsMovesFlagsBeforeTargets(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"flags first unchanged", []string{"--expiry-warn", "68", "example.com"}, []string{"--expiry-warn", "68", "example.com"}},
		{"flag after target", []string{"example.com", "--expiry-warn", "68"}, []string{"--expiry-warn", "68", "example.com"}},
		{"inline value after target", []string{"example.com", "--expiry-warn=68"}, []string{"--expiry-warn=68", "example.com"}},
		{"bool flag after target", []string{"example.com", "--log-findings"}, []string{"--log-findings", "example.com"}},
		{"mixed flags and two targets", []string{"a.com", "--operator", "soc", "b.com", "--enumerate"}, []string{"--operator", "soc", "--enumerate", "a.com", "b.com"}},
		{"double dash ends flags", []string{"--operator", "soc", "--", "--weird.example"}, []string{"--operator", "soc", "--weird.example"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := reorderHeadlessArgs(tc.in)
			if strings.Join(got, " ") != strings.Join(tc.want, " ") {
				t.Errorf("reorderHeadlessArgs(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseHeadlessInputsEmptyErrors(t *testing.T) {
	_, err := parseHeadlessInputs(nil)
	if err == nil {
		t.Fatal("no targets must produce an error")
	}
	if !strings.Contains(err.Error(), "no targets") || !strings.Contains(err.Error(), "usage") {
		t.Errorf("error should point the operator at the usage line: %v", err)
	}
}

func TestParseHeadlessInputsReturnsTargets(t *testing.T) {
	in := []string{"example.com", "example.com:8443"}
	got, err := parseHeadlessInputs(in)
	if err != nil {
		t.Fatalf("valid args returned error: %v", err)
	}
	if len(got) != 2 || got[0] != in[0] || got[1] != in[1] {
		t.Errorf("parseHeadlessInputs = %v, want %v (order preserved)", got, in)
	}
}
