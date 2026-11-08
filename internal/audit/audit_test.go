package audit

import (
	"path/filepath"
	"testing"
	"time"
)

func TestSummarizeAndFile(t *testing.T) {
	now := time.Date(2026, 11, 8, 15, 0, 0, 0, time.UTC)
	events := []Event{
		{Time: now, IP: "100.70.1.2:1", Name: "staging-db/password", Result: "approved", Actor: "claude"},
		{Time: now.Add(-24 * time.Hour), Name: "staging-db/password", Result: "denied"},
		{Time: now.Add(-8 * 24 * time.Hour), Name: "old", Result: "approved"},
	}
	r := Summarize(events, now)
	if len(r.Days) != 7 || r.Days[6].Approved != 1 || r.Days[5].Denied != 1 || r.Days[0].Approved != 0 {
		t.Fatalf("%+v", r.Days)
	}
	dir := t.TempDir()
	l, err := Open(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	l.Add(events[0])
	got := l.Report(now)
	if got.Days[6].Approved != 1 {
		t.Fatalf("%+v", got.Days)
	}
}
