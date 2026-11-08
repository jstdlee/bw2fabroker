// Package audit appends one JSON line per broker decision. The line records the caller address,
// the request name, the time, and the result. It never records a secret value.
package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Event is one audit line.
type Event struct {
	Time   time.Time `json:"time"`
	IP     string    `json:"ip"`
	Name   string    `json:"name"`
	Result string    `json:"result"`
	Actor  string    `json:"actor,omitempty"`
}

// Day is one calendar day of counts, plus bar heights for the admin chart.
type Day struct {
	Label                      string
	Approved, Denied, Rejected int
	Other                      int
	HA, HD, HR, HO             int
}

// Report is the last 7 days, oldest first.
type Report struct {
	Days []Day
	Max  int
}

// Log is the JSONL file.
type Log struct {
	path string
	mu   sync.Mutex
}

// Open creates or opens the audit file, mode 0600.
func Open(path string) (*Log, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	_ = f.Close()
	_ = os.Chmod(path, 0o600)
	return &Log{path: path}, nil
}

// Add appends one event and drops lines older than 8 days when the file is large.
func (l *Log) Add(e Event) {
	if l == nil {
		return
	}
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	_, _ = f.Write(append(b, '\n'))
	_ = f.Close()
	if st, err := os.Stat(l.path); err == nil && st.Size() > 1<<20 {
		l.compact(e.Time.Add(-8 * 24 * time.Hour))
	}
}

func (l *Log) compact(keep time.Time) {
	events := l.read()
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	for _, e := range events {
		if e.Time.Before(keep) {
			continue
		}
		b, err := json.Marshal(e)
		if err != nil {
			continue
		}
		_, _ = f.Write(append(b, '\n'))
	}
}

// Report returns counts for the 7 local days ending today.
func (l *Log) Report(now time.Time) Report {
	if l == nil {
		return emptyReport(now)
	}
	l.mu.Lock()
	events := l.read()
	l.mu.Unlock()
	return Summarize(events, now)
}
func (l *Log) read() []Event {
	f, err := os.Open(l.path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		var e Event
		if json.Unmarshal(sc.Bytes(), &e) == nil && !e.Time.IsZero() {
			out = append(out, e)
		}
	}
	return out
}

func emptyReport(now time.Time) Report {
	return Summarize(nil, now)
}

// Summarize buckets events into 7 local days.
func Summarize(events []Event, now time.Time) Report {
	loc := now.Location()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	days := make([]Day, 7)
	index := map[string]int{}
	for i := range 7 {
		d := today.AddDate(0, 0, i-6)
		label := d.Format("01-02")
		days[i] = Day{Label: label}
		index[d.Format("2006-01-02")] = i
	}
	start := today.AddDate(0, 0, -6)
	for _, e := range events {
		et := e.Time.In(loc)
		if et.Before(start) || !et.Before(today.AddDate(0, 0, 1)) {
			continue
		}
		i, ok := index[et.Format("2006-01-02")]
		if !ok {
			continue
		}
		switch e.Result {
		case "approved", "auto":
			days[i].Approved++
		case "denied":
			days[i].Denied++
		case "rejected":
			days[i].Rejected++
		default:
			days[i].Other++
		}
	}
	max := 1
	for i := range days {
		n := days[i].Approved + days[i].Denied + days[i].Rejected + days[i].Other
		if n > max {
			max = n
		}
	}
	const h = 96
	for i := range days {
		days[i].HA = days[i].Approved * h / max
		days[i].HD = days[i].Denied * h / max
		days[i].HR = days[i].Rejected * h / max
		days[i].HO = days[i].Other * h / max
	}
	return Report{Days: days, Max: max}
}
