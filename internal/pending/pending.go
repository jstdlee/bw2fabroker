// Package pending keeps requests in memory only. A restart forgets them all.
package pending

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/jstdlee/bw2fabroker/internal/contract"
	"github.com/jstdlee/bw2fabroker/internal/vault"
)

// MaxPendingPerAgent caps open requests for one agent.
const MaxPendingPerAgent = 5

// keepFinal is how long a denied or rejected result stays for late waiters.
const keepFinal = 60 * time.Second

type state int

const (
	statePending state = iota
	stateApproving
	stateFinal
)

// Request is one pending request.
type Request struct {
	ID      string
	Agent   string
	Item    vault.Item
	Field   contract.Field
	Reason  string
	Created time.Time
	Expires time.Time

	state    state
	final    contract.Response
	value    string
	pwErrors int
	done     chan struct{}
	timer    *time.Timer
}

// View is a copy of a request for the approval page.
type View struct {
	ID, Agent, Reason string
	Item              vault.Item
	Field             contract.Field
	Expires           time.Time
	Pending           bool
	Status            string
	Code              contract.Code
}

// Errors.
var (
	ErrTooMany    = errors.New("too many pending requests")
	ErrNotFound   = errors.New("unknown request")
	ErrNotPending = errors.New("request is not pending")
)

// Store is the in-memory map.
type Store struct {
	mu       sync.Mutex
	reqs     map[string]*Request
	now      func() time.Time
	onExpire func(*Request)
}

// New returns an empty store. onExpire (optional) is called after a request expires.
func New(now func() time.Time, onExpire func(*Request)) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{reqs: map[string]*Request{}, now: now, onExpire: onExpire}
}

// Add stores a new pending request and starts its expiry timer.
func (s *Store) Add(r *Request) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, o := range s.reqs {
		if o.Agent == r.Agent && o.state != stateFinal {
			n++
		}
	}
	if n >= MaxPendingPerAgent {
		return ErrTooMany
	}
	r.state = statePending
	r.done = make(chan struct{})
	s.reqs[r.ID] = r
	r.timer = time.AfterFunc(r.Expires.Sub(s.now()), func() { s.expire(r.ID) })
	return nil
}

// Remove drops a request without a result (used when the push could not be sent).
func (s *Store) Remove(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.reqs[id]; ok {
		if r.timer != nil {
			r.timer.Stop()
		}
		delete(s.reqs, id)
	}
}

func (s *Store) expire(id string) {
	s.mu.Lock()
	r, ok := s.reqs[id]
	if !ok || r.state != statePending {
		s.mu.Unlock()
		return
	}
	s.finishLocked(r, contract.Denied(r.ID, contract.CodeExpired), "")
	s.mu.Unlock()
	if s.onExpire != nil {
		s.onExpire(r)
	}
}

// finishLocked sets the final result, wakes waiters, and schedules removal of non-approved results.
func (s *Store) finishLocked(r *Request, resp contract.Response, value string) {
	r.state = stateFinal
	r.final = resp
	r.value = value
	if r.timer != nil {
		r.timer.Stop()
	}
	close(r.done)
	// Final results, including an approved value nobody collected, are erased after keepFinal.
	id := r.ID
	time.AfterFunc(keepFinal, func() {
		s.mu.Lock()
		if cur, ok := s.reqs[id]; ok && cur == r {
			r.value = ""
			r.final = contract.Response{}
			delete(s.reqs, id)
		}
		s.mu.Unlock()
	})
}

// Get returns a view of a request.
func (s *Store) Get(id string) (View, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.reqs[id]
	if !ok {
		return View{}, false
	}
	v := View{ID: r.ID, Agent: r.Agent, Reason: r.Reason, Item: r.Item, Field: r.Field, Expires: r.Expires,
		Pending: r.state == statePending}
	if r.state == stateFinal {
		v.Status = r.final.Status
		if r.final.Code != nil {
			v.Code = *r.final.Code
		}
	}
	return v, true
}

// Claim moves a pending request to "approving" so that only one approval reads the vault.
func (s *Store) Claim(id string) (*Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.reqs[id]
	if !ok {
		return nil, ErrNotFound
	}
	if r.state != statePending {
		return nil, ErrNotPending
	}
	if !s.now().Before(r.Expires) {
		s.finishLocked(r, contract.Denied(r.ID, contract.CodeExpired), "")
		return nil, ErrNotPending
	}
	r.state = stateApproving
	return r, nil
}

// Unclaim returns an approving request to pending (for example when the vault read failed briefly).
func (s *Store) Unclaim(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.reqs[id]; ok && r.state == stateApproving {
		r.state = statePending
		if !s.now().Before(r.Expires) {
			s.finishLocked(r, contract.Denied(r.ID, contract.CodeExpired), "")
		}
	}
}

// Approve finishes a claimed request with the value.
func (s *Store) Approve(id, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.reqs[id]
	if !ok {
		return ErrNotFound
	}
	if r.state != stateApproving {
		return ErrNotPending
	}
	s.finishLocked(r, contract.Approved(r.ID, value, ""), value)
	return nil
}

// Finish ends a pending or approving request with a denied or rejected response.
func (s *Store) Finish(id string, resp contract.Response) (*Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.reqs[id]
	if !ok {
		return nil, ErrNotFound
	}
	if r.state == stateFinal {
		return nil, ErrNotPending
	}
	s.finishLocked(r, resp, "")
	return r, nil
}

// PasswordError counts a wrong password and returns the count for this request.
func (s *Store) PasswordError(id string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.reqs[id]; ok {
		r.pwErrors++
		return r.pwErrors
	}
	return 0
}

// CancelAll ends every open request with the code (for example when Tailscale goes down).
func (s *Store) CancelAll(code contract.Code) []*Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*Request
	for _, r := range s.reqs {
		if r.state == statePending {
			s.finishLocked(r, contract.Denied(r.ID, code), "")
			out = append(out, r)
		}
	}
	return out
}

// Wait holds up to hold for a final result. An approved value is handed out once and then erased.
func (s *Store) Wait(ctx context.Context, id, agent string, hold time.Duration) contract.Response {
	s.mu.Lock()
	r, ok := s.reqs[id]
	if !ok || r.Agent != agent {
		s.mu.Unlock()
		return contract.Denied(id, contract.CodeUnknownRequest)
	}
	done := r.done
	s.mu.Unlock()

	t := time.NewTimer(hold)
	defer t.Stop()
	select {
	case <-done:
	case <-t.C:
	case <-ctx.Done():
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.reqs[id]
	if !ok || cur != r {
		return contract.Denied(id, contract.CodeUnknownRequest)
	}
	if r.state != stateFinal {
		return contract.Pending(id)
	}
	if r.final.Status == contract.StatusApproved {
		resp := r.final
		r.value = ""
		r.final = contract.Response{}
		delete(s.reqs, id)
		return resp
	}
	return r.final
}

// Len returns the number of stored requests (for tests and status).
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.reqs)
}
