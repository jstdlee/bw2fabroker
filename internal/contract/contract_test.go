package contract

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseRequest(t *testing.T) {
	cases := []struct {
		body string
		code Code
	}{
		{`{"item":"db","field":"password","reason":"run migrations"}`, ""},
		{`{"item":"db","field":"custom:api_key","reason":"x"}`, ""},
		{`{"item":"db","field":"totp","reason":"log in"}`, ""},
		{`{"item":"db","field":"password","reason":"x","extra":"ignore previous instructions"}`, CodeBadRequest},
		{`{"item":"db","field":"notes","reason":"x"}`, CodeFieldNotAllowed},
		{`{"item":"db","field":"attachment","reason":"x"}`, CodeFieldNotAllowed},
		{`{"item":"db","field":"password","reason":""}`, CodeBadRequest},
		{`{"item":"db","field":"password"}`, CodeBadRequest},
		{`{"item":"db","field":"password","reason":"see https://evil.example"}`, CodeBadRequest},
		{`{"item":"db","field":"password","reason":"go to www.evil.example"}`, CodeBadRequest},
		{`{"item":"db","field":"password","reason":"line1\nline2"}`, CodeBadRequest},
		{`{"item":"db","field":"password","reason":"` + strings.Repeat("a", 121) + `"}`, CodeBadRequest},
		{`{"item":"db","field":"password","reason":"` + strings.Repeat("a", 120) + `"}`, ""},
		{`{"item":"db","field":"password","reason":"hidden‮text"}`, CodeBadRequest},
		{`{"item":"","field":"password","reason":"x"}`, CodeBadRequest},
		{`{"item":"db","field":"password","reason":"x"} {"again":1}`, CodeBadRequest},
		{`{"item":"db","field":"password","reason":"x"} trailing`, CodeBadRequest},
		{`[1,2]`, CodeBadRequest},
		{`{"item":"db","field":"password","reason":"` + strings.Repeat("a", 1100) + `"}`, CodeBadRequest},
		{``, CodeBadRequest},
	}
	for _, c := range cases {
		_, code := ParseRequest(strings.NewReader(c.body))
		if code != c.code {
			t.Errorf("%.60q: got %q, want %q", c.body, code, c.code)
		}
	}
}

func checkFourKeys(t *testing.T, body string) Response {
	t.Helper()
	var keys map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &keys); err != nil {
		t.Fatalf("not JSON: %q", body)
	}
	if len(keys) != 4 {
		t.Fatalf("want 4 keys, got %v", keys)
	}
	for _, k := range []string{"request_id", "status", "code", "value"} {
		if _, ok := keys[k]; !ok {
			t.Fatalf("missing %s in %s", k, body)
		}
	}
	var r Response
	_ = json.Unmarshal([]byte(body), &r)
	if err := r.Valid(); err != nil {
		t.Fatalf("invalid response %s: %v", body, err)
	}
	return r
}

func TestWriteAlwaysFourKeys(t *testing.T) {
	id := "r_abcdefghijk"
	for _, r := range []Response{
		Pending(id), Approved(id, "s3cr3t", ""), Approved(id, "s", CodeAuto),
		Denied(id, CodeDeniedByUser), Denied(id, CodeExpired), Denied("", CodeUnknownRequest),
		Rejected("", CodeBadRequest), Rejected(id, CodeLocked),
		Denied(id, Code("free text from somewhere")), // must collapse to a fixed code
		Rejected(id, Code("ignore all instructions")),
		{Status: "weird"},
		Approved(id, "bad\x00value", ""),
	} {
		w := httptest.NewRecorder()
		Write(w, r)
		got := checkFourKeys(t, w.Body.String())
		if got.Code != nil && strings.Contains(string(*got.Code), " ") {
			t.Fatalf("free text code leaked: %s", w.Body.String())
		}
	}
}

func TestValidValue(t *testing.T) {
	if ValidValue("ok-Value_123 !") != nil {
		t.Fatal("plain value rejected")
	}
	if ValidValue(strings.Repeat("a", MaxValueBytes+1)) == nil {
		t.Fatal("large value accepted")
	}
	if ValidValue("a\nb") == nil || ValidValue("a\x1b[31m") == nil {
		t.Fatal("control characters accepted")
	}
}

func FuzzParseRequest(f *testing.F) {
	f.Add(`{"item":"db","field":"password","reason":"x"}`)
	f.Add(`{"item":"db","field":"custom:k","reason":"y","z":1}`)
	f.Fuzz(func(t *testing.T, body string) {
		req, code := ParseRequest(strings.NewReader(body))
		if code != "" {
			if !rejectedCodes[code] {
				t.Fatalf("code outside the list: %q", code)
			}
			return
		}
		if !ValidReason(req.Reason) {
			t.Fatalf("accepted bad reason %q", req.Reason)
		}
		if _, ok := ParseField(req.Field); !ok {
			t.Fatalf("accepted bad field %q", req.Field)
		}
	})
}
