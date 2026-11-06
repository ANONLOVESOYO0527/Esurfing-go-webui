package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type routerTestTransport struct {
	roundTrip func(*http.Request) (*http.Response, error)
	closed    atomic.Bool
}

func (rt *routerTestTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return rt.roundTrip(r)
}

func (rt *routerTestTransport) CloseIdleConnections() { rt.closed.Store(true) }

func TestRouterClientReportsFailedProbeWithoutReauth(t *testing.T) {
	c, _ := newTestClient(t)
	c.Config.CheckInterval = 20
	var probes, auths atomic.Int32
	rt := &routerTestTransport{roundTrip: func(r *http.Request) (*http.Response, error) {
		if probes.Add(1) == 1 {
			return nil, errors.New("temporary connection failure")
		}
		return &http.Response{StatusCode: 204, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
	}}
	c.HttpClient.Transport = rt
	states := make(chan string, 4)
	c.OnBeforeAuth = func() { auths.Add(1) }
	c.OnStatusChange = func(state string) {
		states <- state
		if state == "online" {
			c.Cancel()
		}
	}
	done := make(chan struct{})
	go func() { c.Start(); close(done) }()
	defer func() { c.Cancel(); <-done }()
	for _, want := range []string{"degraded", "online"} {
		select {
		case got := <-states:
			if got != want {
				t.Fatalf("state = %q, want %q", got, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("no %q state received", want)
		}
	}
	if auths.Load() != 0 {
		t.Fatal("one failed probe must not force reauthentication")
	}
}

func TestRouterClientClosesOldConnectionsOnStop(t *testing.T) {
	c, _ := newTestClient(t)
	rt := &routerTestTransport{roundTrip: func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 204, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
	}}
	c.HttpClient.Transport = rt
	c.OnStatusChange = func(string) { c.Cancel() }
	c.Start()
	if !rt.closed.Load() {
		t.Fatal("stopped client retained idle connections")
	}
}

func TestRouterClientRequestHasAnOverallDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, err := NewClient(&Config{Username: "test", Password: "test", BindInterface: "sys_default"}, ctx, cancel)
	if err != nil {
		t.Fatal(err)
	}
	defer c.heartBeatTicker.Stop()
	deadlineSeen := false
	c.HttpClient.Transport = &routerTestTransport{roundTrip: func(r *http.Request) (*http.Response, error) {
		deadline, ok := r.Context().Deadline()
		if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 31*time.Second {
			return nil, errors.New("request has no bounded overall deadline")
		}
		deadlineSeen = true
		return &http.Response{StatusCode: 204, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
	}}
	if err := c.CheckNetwork(); err != nil {
		t.Fatal(err)
	}
	if !deadlineSeen {
		t.Fatal("network check did not issue a bounded request")
	}
}
