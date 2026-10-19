package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandleHomeRendersForm(t *testing.T) {
	s := New("127.0.0.1:0")
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	s.handleHome(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("home status = %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, `<form action="/run" method="POST">`) ||
		!strings.Contains(body, `name="targets"`) {
		t.Errorf("home page missing form: %s", body)
	}
}

func TestHandleRunEmptyTargetsErrors(t *testing.T) {
	s := New("127.0.0.1:0")
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/run", strings.NewReader(""))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.handleRun(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("run status = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "no targets provided") {
		t.Errorf("empty run should error clearly: %s", w.Body.String())
	}
}

func TestHandleRunCommentOnlyErrors(t *testing.T) {
	// FR-C1: comments and blanks must not count as targets.
	s := New("127.0.0.1:0")
	w := httptest.NewRecorder()
	body := strings.NewReader("targets=%23+only+a+comment")
	r := httptest.NewRequest(http.MethodPost, "/run", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.handleRun(w, r)

	if !strings.Contains(w.Body.String(), "no targets provided") {
		t.Errorf("comment-only run should error: %s", w.Body.String())
	}
}

func TestHandleRunGetRedirects(t *testing.T) {
	s := New("127.0.0.1:0")
	w := httptest.NewRecorder()
	s.handleRun(w, httptest.NewRequest(http.MethodGet, "/run", nil))
	if w.Code != http.StatusSeeOther {
		t.Errorf("GET /run status = %d, want 303", w.Code)
	}
}

func TestServerBindsLoopbackOnly(t *testing.T) {
	// FR-A9: the web UI is local-only; a non-loopback bind request must be
	// forced back to 127.0.0.1.
	s := New("0.0.0.0:9999")
	if !strings.HasPrefix(s.Addr(), "127.0.0.1:") {
		t.Errorf("Server.Addr() = %q, want 127.0.0.1:...", s.Addr())
	}
}
