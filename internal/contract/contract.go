// Package contract defines the only request and response shapes that pass between an agent and the
// broker. No free text passes in either direction: requests with unknown keys are rejected, and
// responses always carry exactly the four keys of Response with a code from the fixed list.
package contract

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Status values.
const (
	StatusPending  = "pending"
	StatusApproved = "approved"
	StatusDenied   = "denied"
	StatusRejected = "rejected"
)

// Code is one value from the fixed list. Nothing else is ever sent in Response.Code.
type Code string

// Codes for approved responses.
const (
	CodeAuto Code = "auto"
)

// Codes for denied responses.
const (
	CodeDeniedByUser          Code = "denied_by_user"
	CodeExpired               Code = "expired"
	CodeTooManyPasswordErrors Code = "too_many_password_errors"
	CodeUnknownRequest        Code = "unknown_request"
)

// Codes for rejected responses.
const (
	CodeBadRequest      Code = "bad_request"
	CodeUnknownItem     Code = "unknown_item"
	CodeAmbiguousItem   Code = "ambiguous_item"
	CodeFieldNotAllowed Code = "field_not_allowed"
	CodeValueTooLarge   Code = "value_too_large"
	CodeLocked          Code = "locked"
	CodeRateLimited     Code = "rate_limited"
	CodeSuspended       Code = "suspended"
	CodeUnauthorized    Code = "unauthorized"
	CodeInternalError   Code = "internal_error"
)

var deniedCodes = map[Code]bool{
	CodeDeniedByUser: true, CodeExpired: true, CodeTooManyPasswordErrors: true, CodeUnknownRequest: true,
}

var rejectedCodes = map[Code]bool{
	CodeBadRequest: true, CodeUnknownItem: true, CodeAmbiguousItem: true, CodeFieldNotAllowed: true,
	CodeValueTooLarge: true, CodeLocked: true, CodeRateLimited: true, CodeSuspended: true,
	CodeUnauthorized: true, CodeInternalError: true,
}

// Limits.
const (
	MaxBodyBytes  = 1024
	MaxReasonLen  = 120
	MaxItemLen    = 200
	MaxCustomName = 64
	MaxValueBytes = 4096
)

// Request is the body of POST /v1/requests.
type Request struct {
	Item   string `json:"item"`
	Field  string `json:"field"`
	Reason string `json:"reason"`
}

// Response is the body of every /v1 response. All four keys are always present.
type Response struct {
	RequestID *string `json:"request_id"`
	Status    string  `json:"status"`
	Code      *Code   `json:"code"`
	Value     *string `json:"value"`
}

// Pending builds a pending response.
func Pending(id string) Response { return Response{RequestID: &id, Status: StatusPending} }

// Approved builds an approved response carrying the value. code is "" or CodeAuto.
func Approved(id, value string, code Code) Response {
	r := Response{RequestID: &id, Status: StatusApproved, Value: &value}
	if code != "" {
		r.Code = &code
	}
	return r
}

// Denied builds a final denied response.
func Denied(id string, code Code) Response {
	if !deniedCodes[code] {
		code = CodeUnknownRequest
	}
	r := Response{Status: StatusDenied, Code: &code}
	if id != "" {
		r.RequestID = &id
	}
	return r
}

// Rejected builds a final rejected response. id may be empty.
func Rejected(id string, code Code) Response {
	if !rejectedCodes[code] {
		code = CodeInternalError
	}
	r := Response{Status: StatusRejected, Code: &code}
	if id != "" {
		r.RequestID = &id
	}
	return r
}

// HTTPStatus maps a response to an HTTP status code. The body is the contract; the status code
// only helps tools like curl.
func (r Response) HTTPStatus() int {
	code := Code("")
	if r.Code != nil {
		code = *r.Code
	}
	switch r.Status {
	case StatusPending:
		return http.StatusAccepted
	case StatusApproved:
		return http.StatusOK
	case StatusDenied:
		switch code {
		case CodeExpired:
			return http.StatusRequestTimeout
		case CodeUnknownRequest:
			return http.StatusNotFound
		}
		return http.StatusForbidden
	}
	switch code {
	case CodeUnauthorized:
		return http.StatusUnauthorized
	case CodeSuspended:
		return http.StatusForbidden
	case CodeUnknownItem:
		return http.StatusNotFound
	case CodeAmbiguousItem:
		return http.StatusConflict
	case CodeRateLimited:
		return http.StatusTooManyRequests
	case CodeLocked:
		return http.StatusServiceUnavailable
	case CodeInternalError:
		return http.StatusInternalServerError
	}
	return http.StatusBadRequest
}

// Final reports whether the status is final.
func (r Response) Final() bool { return r.Status != StatusPending }

// Write sends the response. It is the only way the agent API writes a body.
func Write(w http.ResponseWriter, r Response) {
	if err := r.Valid(); err != nil {
		r = Rejected("", CodeInternalError)
	}
	b, err := json.Marshal(r)
	if err != nil {
		b = []byte(`{"request_id":null,"status":"rejected","code":"internal_error","value":null}`)
	}
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(r.HTTPStatus())
	_, _ = w.Write(append(b, '\n'))
}

// Valid checks that a response follows the contract. Write uses it as a last guard.
func (r Response) Valid() error {
	code := Code("")
	if r.Code != nil {
		code = *r.Code
	}
	if r.RequestID != nil && !ValidRequestID(*r.RequestID) {
		return errors.New("bad request id")
	}
	switch r.Status {
	case StatusPending:
		if r.RequestID == nil || r.Code != nil || r.Value != nil {
			return errors.New("bad pending")
		}
	case StatusApproved:
		if r.RequestID == nil || r.Value == nil || (r.Code != nil && code != CodeAuto) {
			return errors.New("bad approved")
		}
		if err := ValidValue(*r.Value); err != nil && !strings.HasPrefix(*r.Value, "[in env ") {
			return err
		}
	case StatusDenied:
		if !deniedCodes[code] || r.Value != nil {
			return errors.New("bad denied")
		}
	case StatusRejected:
		if !rejectedCodes[code] || r.Value != nil {
			return errors.New("bad rejected")
		}
	default:
		return errors.New("bad status")
	}
	return nil
}

// ValidRequestID reports whether s has the shape of a broker request id.
func ValidRequestID(s string) bool {
	if !strings.HasPrefix(s, "r_") || len(s) < 10 || len(s) > 64 {
		return false
	}
	for _, c := range s[2:] {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// ParseRequest reads and validates a request body. Any problem gives a rejected code.
func ParseRequest(body io.Reader) (Request, Code) {
	raw, err := io.ReadAll(io.LimitReader(body, MaxBodyBytes+1))
	if err != nil || len(raw) > MaxBodyBytes {
		return Request{}, CodeBadRequest
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var req Request
	if err := dec.Decode(&req); err != nil {
		return Request{}, CodeBadRequest
	}
	if dec.More() {
		return Request{}, CodeBadRequest
	}
	if _, err := dec.Token(); err != io.EOF {
		return Request{}, CodeBadRequest
	}
	if !validLine(req.Item, 1, MaxItemLen) {
		return Request{}, CodeBadRequest
	}
	if !ValidReason(req.Reason) {
		return Request{}, CodeBadRequest
	}
	if _, ok := ParseField(req.Field); !ok {
		return Request{}, CodeFieldNotAllowed
	}
	return req, ""
}

// Field is a parsed field name.
type Field struct {
	Kind   string // username, password, totp, uri, notes, custom, card, identity, attachment
	Custom string // name when Kind needs one
}

func (f Field) String() string {
	switch f.Kind {
	case "custom", "card", "identity", "attachment":
		return f.Kind + ":" + f.Custom
	default:
		return f.Kind
	}
}

// ParseField accepts every stored text field. The value still has to pass ValidValue.
func ParseField(s string) (Field, bool) {
	switch s {
	case "username", "password", "totp", "uri", "notes":
		return Field{Kind: s}, true
	}
	kind, name, ok := strings.Cut(s, ":")
	if !ok || !validLine(name, 1, MaxCustomName) {
		return Field{}, false
	}
	switch kind {
	case "custom":
		return Field{Kind: kind, Custom: name}, true
	case "attachment":
		if strings.ContainsAny(name, "/\\") || strings.Contains(name, "..") {
			return Field{}, false
		}
		return Field{Kind: kind, Custom: name}, true
	case "card":
		switch name {
		case "cardholder", "brand", "number", "exp_month", "exp_year", "code":
			return Field{Kind: kind, Custom: name}, true
		}
	case "identity":
		switch name {
		case "title", "first_name", "middle_name", "last_name", "address1", "address2", "address3",
			"city", "state", "postal_code", "country", "company", "email", "phone", "ssn",
			"username", "passport_number", "license_number":
			return Field{Kind: kind, Custom: name}, true
		}
	}
	return Field{}, false
}

// ValidReason: one line, 1-120 printable characters, no URLs.
func ValidReason(s string) bool {
	if !validLine(s, 1, MaxReasonLen) {
		return false
	}
	l := strings.ToLower(s)
	for _, bad := range []string{"://", "www.", "http:", "https:", "mailto:", "data:"} {
		if strings.Contains(l, bad) {
			return false
		}
	}
	return true
}

// ValidValue: at most 4 KB of valid UTF-8 with no control characters.
func ValidValue(s string) error {
	if len(s) > MaxValueBytes || !utf8.ValidString(s) {
		return errors.New("value too large or not text")
	}
	for _, c := range s {
		if unicode.IsControl(c) || c == utf8.RuneError {
			return errors.New("value has control characters")
		}
	}
	return nil
}

func validLine(s string, minRunes, maxRunes int) bool {
	if !utf8.ValidString(s) {
		return false
	}
	n := utf8.RuneCountInString(s)
	if n < minRunes || n > maxRunes || strings.TrimSpace(s) == "" {
		return false
	}
	for _, c := range s {
		if unicode.IsControl(c) || !unicode.IsPrint(c) && c != ' ' {
			return false
		}
		// Bidi overrides and zero-width characters can hide text on the approval page.
		if unicode.Is(unicode.Cf, c) {
			return false
		}
	}
	return true
}
