package main

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

type countedLogArgument struct{ calls *int }

func (s countedLogArgument) String() string {
	*s.calls++
	return "formatted"
}

func TestClientDisabledLogsSkipFormattingAndSinks(t *testing.T) {
	h := NewLogHub(10, "")
	defer h.Close()
	h.SetLevel(LevelInfo)
	var stdout bytes.Buffer
	callbackCalls, formatCalls := 0, 0
	c := &Client{
		Log:        log.New(&stdout, "", 0),
		LogEnabled: h.Enabled,
		OnLog: func(level, msg string) {
			callbackCalls++
			h.Add(level, msg)
		},
	}
	c.logf(LevelDebug, "value: %s", countedLogArgument{&formatCalls})
	c.logln(LevelDebug, "hidden")
	if formatCalls != 0 || callbackCalls != 0 || stdout.Len() != 0 || len(h.GetAll()) != 0 {
		t.Fatalf("disabled logs did work: formatting=%d callbacks=%d stdout=%q", formatCalls, callbackCalls, stdout.String())
	}
	h.SetLevel(LevelDebug)
	c.logf(LevelDebug, "value: %s", countedLogArgument{&formatCalls})
	c.logln(LevelWarn, "warning")
	if formatCalls != 1 || callbackCalls != 2 {
		t.Fatalf("enabled log formatting=%d callbacks=%d; want 1 and 2", formatCalls, callbackCalls)
	}
	if !strings.Contains(stdout.String(), "[debug] value: formatted") || !strings.Contains(stdout.String(), "[warn] warning") {
		t.Fatalf("enabled stdout messages missing: %q", stdout.String())
	}
	if entries := h.GetAll(); len(entries) != 2 || entries[0].Message != "value: formatted" || entries[1].Message != "warning" {
		t.Fatalf("enabled callback messages missing: %+v", entries)
	}
}

func TestClientWithoutLogFilterKeepsLogging(t *testing.T) {
	var stdout bytes.Buffer
	var messages []string
	c := &Client{
		Log: log.New(&stdout, "", 0),
		OnLog: func(level, msg string) {
			messages = append(messages, level+":"+msg)
		},
	}
	c.logf(LevelDebug, "number %d", 7)
	c.logln(LevelError, "error")
	if len(messages) != 2 || messages[0] != "debug:number 7" || messages[1] != "error:error" {
		t.Fatalf("legacy callbacks changed: %v", messages)
	}
	if !strings.Contains(stdout.String(), "[debug] number 7") || !strings.Contains(stdout.String(), "[error] error") {
		t.Fatalf("legacy stdout changed: %q", stdout.String())
	}
}
