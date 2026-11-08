package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jstdlee/bw2fabroker/internal/contract"
)

type bwLogin struct {
	Username *string `json:"username"`
	Password *string `json:"password"`
	Totp     *string `json:"totp"`
	Uris     []struct {
		URI *string `json:"uri"`
	} `json:"uris"`
}

type bwField struct {
	Name  *string `json:"name"`
	Value *string `json:"value"`
	Type  int     `json:"type"`
}

type bwAttachment struct {
	FileName *string `json:"fileName"`
}

type bwCard struct {
	CardholderName *string `json:"cardholderName"`
	Brand          *string `json:"brand"`
	Number         *string `json:"number"`
	ExpMonth       *string `json:"expMonth"`
	ExpYear        *string `json:"expYear"`
	Code           *string `json:"code"`
}

type bwIdentity struct {
	Title          *string `json:"title"`
	FirstName      *string `json:"firstName"`
	MiddleName     *string `json:"middleName"`
	LastName       *string `json:"lastName"`
	Address1       *string `json:"address1"`
	Address2       *string `json:"address2"`
	Address3       *string `json:"address3"`
	City           *string `json:"city"`
	State          *string `json:"state"`
	PostalCode     *string `json:"postalCode"`
	Country        *string `json:"country"`
	Company        *string `json:"company"`
	Email          *string `json:"email"`
	Phone          *string `json:"phone"`
	SSN            *string `json:"ssn"`
	Username       *string `json:"username"`
	PassportNumber *string `json:"passportNumber"`
	LicenseNumber  *string `json:"licenseNumber"`
}

func filled(p *string) bool { return p != nil && *p != "" }

func (b *BW) folderOf(id *string) string {
	if id == nil {
		return ""
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.folders[*id]
}

func (b *BW) listItems(ctx context.Context, search string) ([]bwItem, error) {
	args := []string{"list", "items"}
	if search != "" {
		args = append(args, "--search", search)
	}
	out, err := b.run(ctx, true, nil, args...)
	if err != nil {
		return nil, err
	}
	var items []bwItem
	if err := json.Unmarshal(out, &items); err != nil {
		return nil, err
	}
	return items, nil
}

// Search returns items whose name contains query. Secret values are not copied out.
func (b *BW) Search(ctx context.Context, query string) ([]CatalogItem, error) {
	items, err := b.listItems(ctx, query)
	if err != nil {
		return nil, err
	}
	q := strings.ToLower(query)
	var out []CatalogItem
	for _, it := range items {
		if q != "" && !strings.Contains(strings.ToLower(it.Name), q) {
			continue
		}
		out = append(out, CatalogItem{ID: it.ID, Name: it.Name, Folder: b.folderOf(it.FolderID), Fields: fieldNames(it)})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name == out[j].Name {
			return out[i].ID < out[j].ID
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// List returns every item name and its field names.
func (b *BW) List(ctx context.Context) ([]CatalogItem, error) { return b.Search(ctx, "") }

func fieldNames(it bwItem) []string {
	var out []string
	add := func(s string) { out = append(out, s) }
	if it.Login != nil {
		if filled(it.Login.Username) {
			add("username")
		}
		if filled(it.Login.Password) {
			add("password")
		}
		if filled(it.Login.Totp) {
			add("totp")
		}
		if len(it.Login.Uris) > 0 && filled(it.Login.Uris[0].URI) {
			add("uri")
		}
	}
	if filled(it.Notes) {
		add("notes")
	}
	if it.Card != nil {
		for _, p := range []struct {
			n string
			v *string
		}{
			{"cardholder", it.Card.CardholderName}, {"brand", it.Card.Brand}, {"number", it.Card.Number},
			{"exp_month", it.Card.ExpMonth}, {"exp_year", it.Card.ExpYear}, {"code", it.Card.Code},
		} {
			if filled(p.v) {
				add("card:" + p.n)
			}
		}
	}
	if it.Identity != nil {
		id := it.Identity
		for _, p := range []struct {
			n string
			v *string
		}{
			{"title", id.Title}, {"first_name", id.FirstName}, {"middle_name", id.MiddleName}, {"last_name", id.LastName},
			{"address1", id.Address1}, {"address2", id.Address2}, {"address3", id.Address3},
			{"city", id.City}, {"state", id.State}, {"postal_code", id.PostalCode}, {"country", id.Country},
			{"company", id.Company}, {"email", id.Email}, {"phone", id.Phone}, {"ssn", id.SSN},
			{"username", id.Username}, {"passport_number", id.PassportNumber}, {"license_number", id.LicenseNumber},
		} {
			if filled(p.v) {
				add("identity:" + p.n)
			}
		}
	}
	counts := map[string]int{}
	for _, fl := range it.Fields {
		if fl.Name == nil || fl.Type == 3 || !filled(fl.Value) {
			continue
		}
		counts[*fl.Name]++
	}
	var custom []string
	for name, n := range counts {
		if n == 1 {
			custom = append(custom, "custom:"+name)
		}
	}
	sort.Strings(custom)
	out = append(out, custom...)
	for _, a := range it.Attachments {
		if a.FileName != nil && *a.FileName != "" {
			add("attachment:" + *a.FileName)
		}
	}
	return out
}

func namedAttachment(it bwItem, name string) bool {
	for _, a := range it.Attachments {
		if a.FileName != nil && *a.FileName == name {
			return true
		}
	}
	return false
}

func (b *BW) readAttachment(ctx context.Context, itemID, name string) (string, error) {
	dir, err := os.MkdirTemp("", "bwbroker-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	if _, err := b.run(ctx, true, nil, "get", "attachment", name, "--itemid", itemID, "--output", dir); err != nil {
		return "", err
	}
	f, err := os.Open(filepath.Join(dir, name))
	if err != nil {
		return "", ErrNoField
	}
	defer f.Close()
	buf := make([]byte, contract.MaxValueBytes+1)
	n, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return "", err
	}
	return string(buf[:n]), nil
}

// Exec runs bw with the broker session. The caller must not write stdout into the audit log.
func (b *BW) Exec(ctx context.Context, args []string) (string, string, error) {
	if len(args) == 0 || len(args) > 32 {
		return "", "", errors.New("bw needs 1 to 32 arguments")
	}
	for _, a := range args {
		if a == "" || len(a) > 500 || strings.ContainsAny(a, "\n\r\x00") {
			return "", "", errors.New("bad bw argument")
		}
	}
	withSession := b.Unlocked()
	if !withSession && args[0] != "status" && args[0] != "login" && args[0] != "config" && args[0] != "logout" {
		return "", "", ErrLocked
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, b.Path, append(args, "--nointeraction")...)
	var extra []string
	if withSession {
		b.mu.RLock()
		extra = append(extra, "BW_SESSION="+b.session)
		b.mu.RUnlock()
	}
	cmd.Env = b.env(extra...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	stderr := strings.TrimSpace(errb.String())
	if len(stderr) > 400 {
		stderr = stderr[:400]
	}
	return out.String(), stderr, err
}

func derefField(p *string) (string, error) {
	if !filled(p) {
		return "", ErrNoField
	}
	return *p, nil
}

func cardField(c *bwCard, name string) (string, error) {
	if c == nil {
		return "", ErrNoField
	}
	switch name {
	case "cardholder":
		return derefField(c.CardholderName)
	case "brand":
		return derefField(c.Brand)
	case "number":
		return derefField(c.Number)
	case "exp_month":
		return derefField(c.ExpMonth)
	case "exp_year":
		return derefField(c.ExpYear)
	case "code":
		return derefField(c.Code)
	}
	return "", ErrNoField
}

func identityField(id *bwIdentity, name string) (string, error) {
	if id == nil {
		return "", ErrNoField
	}
	switch name {
	case "title":
		return derefField(id.Title)
	case "first_name":
		return derefField(id.FirstName)
	case "middle_name":
		return derefField(id.MiddleName)
	case "last_name":
		return derefField(id.LastName)
	case "address1":
		return derefField(id.Address1)
	case "address2":
		return derefField(id.Address2)
	case "address3":
		return derefField(id.Address3)
	case "city":
		return derefField(id.City)
	case "state":
		return derefField(id.State)
	case "postal_code":
		return derefField(id.PostalCode)
	case "country":
		return derefField(id.Country)
	case "company":
		return derefField(id.Company)
	case "email":
		return derefField(id.Email)
	case "phone":
		return derefField(id.Phone)
	case "ssn":
		return derefField(id.SSN)
	case "username":
		return derefField(id.Username)
	case "passport_number":
		return derefField(id.PassportNumber)
	case "license_number":
		return derefField(id.LicenseNumber)
	}
	return "", ErrNoField
}
