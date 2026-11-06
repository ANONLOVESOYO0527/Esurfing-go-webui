package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestLogHubRetainsRecentEntriesInOrder(t *testing.T) {
	h := NewLogHub(3, "")
	defer h.Close()
	for _, msg := range []string{"one", "two", "three", "four", "five"} {
		h.Add(LevelInfo, msg)
	}
	entries := h.GetAll()
	if len(entries) != 3 {
		t.Fatalf("retained %d entries, want 3", len(entries))
	}
	for i, want := range []string{"three", "four", "five"} {
		if entries[i].Message != want {
			t.Errorf("entry %d = %q, want %q", i, entries[i].Message, want)
		}
	}
	entries[0].Message = "modified snapshot"
	if got := h.GetAll()[0].Message; got != "three" {
		t.Errorf("snapshot mutation affected retained entries: %q", got)
	}
	h.Add(LevelInfo, "six")
	if got := h.GetAll()[0].Message; got != "four" {
		t.Errorf("snapshot mutation affected history: %q", got)
	}
}

func TestLogHubEmptyHistoryStillPublishes(t *testing.T) {
	h := NewLogHub(0, "")
	defer h.Close()
	ch := h.Subscribe()
	defer h.Unsubscribe(ch)
	h.Add(LevelWarn, "important")
	if entries := h.GetAll(); len(entries) != 0 {
		t.Fatalf("zero capacity retained %d entries", len(entries))
	}
	select {
	case entry := <-ch:
		if entry.Message != "important" {
			t.Errorf("published %q", entry.Message)
		}
	default:
		t.Fatal("zero-capacity history must still publish to subscribers")
	}
}

func TestLogHubFilteringAndSubscriptionsSurviveWrap(t *testing.T) {
	h := NewLogHub(1, "")
	defer h.Close()
	h.SetLevel(LevelWarn)
	ch := h.Subscribe()
	defer h.Unsubscribe(ch)
	h.Add(LevelInfo, "filtered")
	h.Add(LevelWarn, "first")
	h.Add(LevelError, "second")
	for _, want := range []string{"first", "second"} {
		select {
		case got := <-ch:
			if got.Message != want {
				t.Fatalf("subscriber got %q, want %q", got.Message, want)
			}
		default:
			t.Fatalf("missing subscriber message %q", want)
		}
	}
	select {
	case unexpected := <-ch:
		t.Fatalf("unexpected message: %+v", unexpected)
	default:
	}
	if got := h.GetAll(); len(got) != 1 || got[0].Message != "second" {
		t.Fatalf("wrong wrapped history: %+v", got)
	}
	h.SetLevel(LevelDebug)
	h.Add(LevelDebug, "enabled again")
	if got := h.GetAll()[0].Message; got != "enabled again" {
		t.Fatalf("level change did not take effect: %q", got)
	}
}

func TestLogHubConcurrentReadersAndWriters(t *testing.T) {
	h := NewLogHub(32, "")
	defer h.Close()
	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				h.Add(LevelWarn, fmt.Sprintf("%d:%d", worker, i))
				if entries := h.GetAll(); len(entries) > 32 {
					t.Errorf("retention limit exceeded: %d", len(entries))
				}
				h.SetLevel(LevelInfo)
				ch := h.Subscribe()
				h.Unsubscribe(ch)
			}
		}(worker)
	}
	wg.Wait()
	if got := len(h.GetAll()); got != 32 {
		t.Errorf("retained %d entries, want 32", got)
	}
}

func TestLogHubWrappedHistoryStillPersistsAllAcceptedEntries(t *testing.T) {
	dir := t.TempDir()
	h := NewLogHub(2, dir)
	h.SetLevel(LevelInfo)
	h.Add(LevelDebug, "filtered")
	for i := 0; i < 5; i++ {
		h.Add(LevelInfo, fmt.Sprintf("message %d", i))
	}
	h.Close()
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil || len(files) != 1 {
		t.Fatalf("log files = %v, error = %v", files, err)
	}
	data, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 5 {
		t.Fatalf("persisted %d entries, want all 5 accepted messages", len(lines))
	}
	for i, line := range lines {
		var entry LogEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatal(err)
		}
		if want := fmt.Sprintf("message %d", i); entry.Message != want {
			t.Errorf("disk entry %d = %q, want %q", i, entry.Message, want)
		}
	}
}

func BenchmarkLogHubFullHistory(b *testing.B) {
	h := NewLogHub(1000, "")
	defer h.Close()
	for i := 0; i < 1000; i++ {
		h.Add(LevelInfo, "existing entry")
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Add(LevelInfo, "steady-state log message")
	}
}

func TestLogHubFullHistoryAllocationBudget(t *testing.T) {
	result := testing.Benchmark(BenchmarkLogHubFullHistory)
	if bytes := result.AllocedBytesPerOp(); bytes > 1024 {
		t.Fatalf("full history allocates %d bytes/log; budget is 1024", bytes)
	}
	t.Logf("full history: %d bytes/log, %d allocations/log", result.AllocedBytesPerOp(), result.AllocsPerOp())
}

func TestLogHubRetentionIncludesTheCurrentFile(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 5; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("2000-01-01_00-00-%02d.000.json", i)), []byte("old\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	h := NewLogHub(10, dir)
	defer h.Close()
	h.maxFileSize = 1
	for i := 0; i < 8; i++ {
		h.Add(LevelInfo, fmt.Sprintf("rotate %d", i))
		files, err := filepath.Glob(filepath.Join(dir, "*.json"))
		if err != nil || len(files) > 3 {
			t.Fatalf("rotation %d retained %d files (including current), error=%v", i, len(files), err)
		}
	}
}

func TestLogHubRetentionProtectsCurrentFileAfterClockRollback(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 3; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("2099-01-01_00-00-%02d.000.json", i)), []byte("future log\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	h := NewLogHub(10, dir)
	current := h.logFile.Name()
	h.Add(LevelInfo, "current log must remain readable")
	h.Close()
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	if len(files) > 3 {
		t.Fatalf("kept %d files after clock rollback, want at most 3", len(files))
	}
	data, err := os.ReadFile(current)
	if err != nil || !strings.Contains(string(data), "current log must remain readable") {
		t.Fatalf("current log lost after clock rollback: %v", err)
	}
}
