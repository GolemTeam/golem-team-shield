package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPolicyCheckDeny(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"action": "block", "reason": "nope"})
	}))
	defer srv.Close()

	denied, reason := policyCheck(srv.URL, "bash -c rm", "bash")
	if !denied || reason != "nope" {
		t.Fatalf("denied=%v reason=%q", denied, reason)
	}
}

func TestPolicyCheckAllow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"action": "none"})
	}))
	defer srv.Close()

	denied, _ := policyCheck(srv.URL, "bash -c ls", "bash")
	if denied {
		t.Fatal("expected allow")
	}
}

func TestPolicyCheckFailOpen(t *testing.T) {
	denied, _ := policyCheck("http://127.0.0.1:1", "x", "bash")
	if denied {
		t.Fatal("transport failure must fail-open")
	}
}
