package httpproxy

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHTTP_GetRoundTrip(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s", r.Method)
		}
		if r.URL.Path != "/hello" {
			t.Errorf("path = %s", r.URL.Path)
		}
		w.Header().Set("X-Custom", "yes")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"hello":"world"}`))
	}))
	defer srv.Close()

	h := New(nil)
	res, err := h.Do(context.Background(), Request{Method: "GET", URL: srv.URL + "/hello"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if res.Status != 200 {
		t.Errorf("status = %d", res.Status)
	}
	if !strings.Contains(string(res.Body), "hello") {
		t.Errorf("body = %q", res.Body)
	}
	if res.Headers.Get("X-Custom") != "yes" {
		t.Errorf("headers missing X-Custom: %v", res.Headers)
	}
}

func TestHTTP_PostWithBody(t *testing.T) {
	t.Parallel()
	var received []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 4096)
		n, _ := r.Body.Read(b)
		received = append(received, b[:n]...)
		w.WriteHeader(201)
	}))
	defer srv.Close()

	h := New(nil)
	res, err := h.Do(context.Background(), Request{
		Method:  "POST",
		URL:     srv.URL + "/post",
		Headers: map[string]string{"Content-Type": "application/json"},
		Body:    []byte(`{"k":"v"}`),
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if res.Status != 201 {
		t.Errorf("status = %d", res.Status)
	}
	if string(received) != `{"k":"v"}` {
		t.Errorf("server got %q", received)
	}
}

func TestHTTP_Truncation(t *testing.T) {
	t.Parallel()
	big := bytes.Repeat([]byte{'a'}, InlineBodyLimit+100)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(big)
	}))
	defer srv.Close()

	h := New(nil)
	res, err := h.Do(context.Background(), Request{URL: srv.URL + "/"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Truncated {
		t.Errorf("expected Truncated=true")
	}
	if int64(len(res.Body)) != InlineBodyLimit {
		t.Errorf("body len = %d, want %d", len(res.Body), InlineBodyLimit)
	}
}

func TestHTTP_Timeout(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
	}))
	defer srv.Close()

	h := New(nil)
	_, err := h.Do(context.Background(), Request{URL: srv.URL + "/slow", Timeout: 50 * time.Millisecond})
	if err == nil {
		t.Fatalf("expected timeout error")
	}
}

func TestHTTP_DefaultsToGet(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s", r.Method)
		}
	}))
	defer srv.Close()
	h := New(nil)
	_, err := h.Do(context.Background(), Request{URL: srv.URL + "/"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestHTTP_NoURL(t *testing.T) {
	t.Parallel()
	h := New(nil)
	if _, err := h.Do(context.Background(), Request{Method: "GET"}); err == nil {
		t.Fatal("expected error for missing URL")
	}
}

func TestHTTP_HeadersPropagate(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Trace") != "abc" {
			t.Errorf("X-Trace = %q", r.Header.Get("X-Trace"))
		}
	}))
	defer srv.Close()
	h := New(nil)
	_, err := h.Do(context.Background(), Request{URL: srv.URL + "/", Headers: map[string]string{"X-Trace": "abc"}})
	if err != nil {
		t.Fatal(err)
	}
}
