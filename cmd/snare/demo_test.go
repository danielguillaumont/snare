package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

// M4e §3 exit: the demo serves a dashboard showing a Critical touch, and leaves nothing behind.
func TestDemo(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan demoInfo, 1)
	done := make(chan error, 1)
	var out bytes.Buffer
	go func() {
		done <- runDemo(ctx, demoOptions{HTTP: freeAddr(t), Admin: freeAddr(t), Dashboard: freeAddr(t),
			ready: func(i demoInfo) { ready <- i }}, &out)
	}()
	var info demoInfo
	select {
	case info = <-ready:
	case err := <-done:
		t.Fatalf("demo exited early: %v", err)
	case <-time.After(20 * time.Second):
		t.Fatal("demo not ready")
	}
	if !strings.Contains(out.String(), info.ViewerKey) {
		t.Fatal("viewer key not printed")
	}

	// Sign in as a person would, and look for the Critical touch.
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, Timeout: 5 * time.Second}
	resp, err := c.Get(info.DashboardURL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	m := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindSubmatch(page)
	if m == nil {
		t.Fatalf("no csrf field: %s", page)
	}
	resp, err = c.PostForm(info.DashboardURL+"/login", url.Values{"csrf": {string(m[1])}, "key": {info.ViewerKey}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	var body string
	for i := 0; i < 50; i++ { // the second touch is recorded asynchronously to the request
		resp, err = c.Get(info.DashboardURL + "/")
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if body = string(b); strings.Contains(body, "critical · 2 tripwires") {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	for _, want := range []string{"critical · 2 tripwires", "<b>3</b> tokens", "refund runbook"} {
		if !strings.Contains(body, want) {
			t.Fatalf("dashboard lacks %q", want)
		}
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("demo did not stop")
	}
	if _, err := os.Stat(info.Dir); !os.IsNotExist(err) {
		t.Fatalf("demo directory left behind: %v", err)
	}
}
