package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Exercise Start itself: a failed public probe must not replace a working session.
func TestFailedProbePreservesHealthySession(t *testing.T) {
	c, _ := newTestClient(t)
	c.Config.CheckInterval = 2
	c.authed.Store(true)
	c.cipher = NewCipher(AlgoXTea)
	c.KeepUrl = "http://session.invalid/keep"
	var probes atomic.Int32
	confirmed := make(chan struct{}, 1)
	auth := make(chan struct{}, 1)
	c.OnHeartbeat = func(int) {
		select {
		case confirmed <- struct{}{}:
		default:
		}
	}
	c.OnBeforeAuth = func() {
		select {
		case auth <- struct{}{}:
		default:
		}
		c.Cancel()
	}
	c.HttpClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		status := http.StatusServiceUnavailable
		var body []byte
		if r.URL.Host == "session.invalid" {
			status = http.StatusOK
			body, _ = c.cipher.Encrypt([]byte(`<response><interval>60</interval></response>`))
		} else {
			probes.Add(1)
		}
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(body)), Request: r}, nil
	})
	done := make(chan struct{})
	go func() { defer close(done); c.Start() }()
	t.Cleanup(func() { c.Cancel(); <-done })
	select {
	case <-auth:
		t.Fatal("probe outage triggered re-authentication of a healthy session")
	case <-confirmed:
		if probes.Load() < blackholeReauthThreshold {
			t.Fatal("heartbeat confirmation ran before repeated probe failures")
		}
	case <-time.After(time.Second):
		t.Fatal("session was not checked after repeated probe failures")
	}
}

// Public Internet access does not prove that the campus heartbeat still works.
func TestSuccessfulProbesDoNotHideHeartbeatFailures(t *testing.T) {
	c, _ := newTestClient(t)
	c.Config.CheckInterval = 1
	c.authed.Store(true)
	c.cipher = NewCipher(AlgoXTea)
	c.KeepUrl = "http://session.invalid/keep"
	c.heartBeatTicker.Reset(10 * time.Millisecond)
	auth := make(chan struct{}, 1)
	c.OnBeforeAuth = func() { auth <- struct{}{}; c.Cancel() }
	c.HttpClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		status := http.StatusNoContent
		if r.Method == http.MethodPost {
			status = http.StatusServiceUnavailable
		}
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(nil)), Request: r}, nil
	})
	done := make(chan struct{})
	go func() { defer close(done); c.Start() }()
	t.Cleanup(func() { c.Cancel(); <-done })
	select {
	case <-auth:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("successful probes kept resetting the heartbeat failure count")
	}
}

func TestRepeatedProbeFailuresStillRecoverDeadSessions(t *testing.T) {
	for _, authenticated := range []bool{false, true} {
		t.Run(map[bool]string{false: "not authenticated", true: "dead session"}[authenticated], func(t *testing.T) {
			c, _ := newTestClient(t)
			c.Config.CheckInterval = 2
			c.authed.Store(authenticated)
			c.cipher = NewCipher(AlgoXTea)
			c.KeepUrl = "http://session.invalid/keep"
			auth := make(chan struct{}, 1)
			c.OnBeforeAuth = func() { auth <- struct{}{}; c.Cancel() }
			c.HttpClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				return nil, errors.New("network unreachable")
			})
			done := make(chan struct{})
			go func() { defer close(done); c.Start() }()
			t.Cleanup(func() { c.Cancel(); <-done })
			select {
			case <-auth:
			case <-time.After(time.Second):
				t.Fatal("network blackhole no longer triggers recovery")
			}
		})
	}
}

func TestProbeHasBoundedDeadline(t *testing.T) {
	c, _ := newTestClient(t)
	c.HttpClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		deadline, ok := r.Context().Deadline()
		if !ok || time.Until(deadline) > 5*time.Second {
			return nil, errors.New("public probe can block the heartbeat loop indefinitely")
		}
		return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(bytes.NewReader(nil)), Request: r}, nil
	})
	if err := c.CheckNetwork(); err != nil {
		t.Fatal(err)
	}
}

func TestNewClientBoundsResponseBodyReads(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, err := NewClient(&Config{Username: "test", Password: "test"}, ctx, cancel)
	if err != nil {
		t.Fatal(err)
	}
	defer c.heartBeatTicker.Stop()
	defer c.HttpClient.CloseIdleConnections()
	if c.HttpClient.Timeout <= 0 || c.HttpClient.Timeout > 30*time.Second {
		t.Fatal("authentication and heartbeat response bodies have no bounded read time")
	}
}

// A truncated UDP answer must retry over TCP to the configured DNS server.
func TestCustomResolverFallsBackToTCP(t *testing.T) {
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tcp.Close() })
	udp, err := net.ListenPacket("udp4", tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udp.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, peer, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 12 {
				continue
			}
			answer := append([]byte(nil), buf[:n]...)
			answer[2], answer[3] = 0x83, 0x80 // response, truncated, recursion available
			_, _ = udp.WriteTo(answer, peer)
		}
	}()
	go func() {
		conn, err := tcp.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		var size [2]byte
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			return
		}
		query := make([]byte, binary.BigEndian.Uint16(size[:]))
		if _, err := io.ReadFull(conn, query); err != nil || len(query) < 12 {
			return
		}
		// Drop the request's EDNS additional record before adding the answer.
		end := 12
		for end < len(query) && query[end] != 0 {
			end += 1 + int(query[end])
		}
		end += 5 // root label, QTYPE, QCLASS
		if end > len(query) {
			return
		}
		query = query[:end]
		query[10], query[11] = 0, 0
		query[2], query[3], query[6], query[7] = 0x81, 0x80, 0, 1
		query = append(query, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 7)
		binary.BigEndian.PutUint16(size[:], uint16(len(query)))
		_, _ = conn.Write(append(size[:], query...))
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	resolver := GetResolver(&Config{DnsAddress: tcp.Addr().String()}, net.ParseIP("127.0.0.1"))
	ips, err := resolver.LookupIP(ctx, "ip4", "resolver-test.invalid")
	if err != nil {
		t.Fatalf("TCP fallback failed: %v", err)
	}
	if len(ips) != 1 || !ips[0].Equal(net.ParseIP("203.0.113.7")) {
		t.Fatalf("unexpected DNS answer: %v", ips)
	}
}
