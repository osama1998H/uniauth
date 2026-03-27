package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/osama1998h/uniauth/internal/domain"
)

// TestHandleServiceError verifies that each sentinel domain error maps to the
// correct HTTP status code and that the response body is valid JSON with an
// "error" field.
func TestHandleServiceError(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{
			name:       "ErrNotFound → 404",
			err:        domain.ErrNotFound,
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "ErrAlreadyExists → 409",
			err:        domain.ErrAlreadyExists,
			wantStatus: http.StatusConflict,
		},
		{
			name:       "ErrServiceUnavailable → 503",
			err:        domain.ErrServiceUnavailable,
			wantStatus: http.StatusServiceUnavailable,
		},
		{
			name:       "ErrInvalidCredentials → 401",
			err:        domain.ErrInvalidCredentials,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "ErrUnauthorized → 401",
			err:        domain.ErrUnauthorized,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "ErrForbidden → 403",
			err:        domain.ErrForbidden,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "ErrTokenExpired → 401",
			err:        domain.ErrTokenExpired,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "ErrTokenInvalid → 401",
			err:        domain.ErrTokenInvalid,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "ErrUserInactive → 403",
			err:        domain.ErrUserInactive,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "ErrOrgInactive → 403",
			err:        domain.ErrOrgInactive,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "ErrWeakPassword → 400",
			err:        domain.ErrWeakPassword,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "ErrAPIKeyRevoked → 401",
			err:        domain.ErrAPIKeyRevoked,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "ErrAPIKeyExpired → 401",
			err:        domain.ErrAPIKeyExpired,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "unknown error → 500",
			err:        fmt.Errorf("some unexpected error"),
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "wrapped ErrNotFound → 404",
			err:        fmt.Errorf("service layer: %w", domain.ErrNotFound),
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "wrapped ErrWeakPassword → 400",
			err:        fmt.Errorf("validate: %w", domain.ErrWeakPassword),
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			handleServiceError(w, tc.err)

			if w.Code != tc.wantStatus {
				t.Errorf("status: got %d, want %d", w.Code, tc.wantStatus)
			}
			if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				t.Errorf("Content-Type: got %q, want application/json", ct)
			}
			var body map[string]string
			if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
				t.Fatalf("response body is not valid JSON: %v", err)
			}
			if _, ok := body["error"]; !ok {
				t.Error("response body should contain an 'error' key")
			}
		})
	}
}

func TestWriteJSON(t *testing.T) {
	t.Run("sets Content-Type and status", func(t *testing.T) {
		w := httptest.NewRecorder()
		writeJSON(w, http.StatusCreated, map[string]string{"key": "value"})

		if w.Code != http.StatusCreated {
			t.Errorf("status: got %d, want 201", w.Code)
		}
		if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			t.Errorf("Content-Type: got %q, want application/json", ct)
		}
	})

	t.Run("encodes value as JSON", func(t *testing.T) {
		w := httptest.NewRecorder()
		writeJSON(w, http.StatusOK, map[string]string{"hello": "world"})

		var body map[string]string
		if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
			t.Fatalf("body is not valid JSON: %v", err)
		}
		if body["hello"] != "world" {
			t.Errorf("body[hello]: got %q, want world", body["hello"])
		}
	})
}

func TestWriteError(t *testing.T) {
	w := httptest.NewRecorder()
	writeError(w, http.StatusBadRequest, "invalid input")

	if w.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want 400", w.Code)
	}
	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	if body["error"] != "invalid input" {
		t.Errorf("error message: got %q, want 'invalid input'", body["error"])
	}
}

func TestDecodeJSON(t *testing.T) {
	t.Run("valid JSON", func(t *testing.T) {
		var dest struct{ Name string }
		r := httptest.NewRequest("POST", "/", strings.NewReader(`{"name":"alice"}`))
		r.Header.Set("Content-Type", "application/json")
		if err := decodeJSON(r, &dest); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dest.Name != "alice" {
			t.Errorf("Name: got %q, want alice", dest.Name)
		}
	})

	t.Run("malformed JSON returns error", func(t *testing.T) {
		var dest struct{ Name string }
		r := httptest.NewRequest("POST", "/", strings.NewReader(`{not valid}`))
		if err := decodeJSON(r, &dest); err == nil {
			t.Fatal("expected error for malformed JSON, got nil")
		}
	})

	t.Run("empty body returns error", func(t *testing.T) {
		var dest struct{ Name string }
		r := httptest.NewRequest("POST", "/", strings.NewReader(""))
		if err := decodeJSON(r, &dest); err == nil {
			t.Fatal("expected error for empty body, got nil")
		}
	})
}
