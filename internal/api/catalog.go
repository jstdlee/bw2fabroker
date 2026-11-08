package api

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/jstdlee/bw2fabroker/internal/contract"
	"github.com/jstdlee/bw2fabroker/internal/vault"
)

type catalogBody struct {
	Items []vault.CatalogItem `json:"items"`
}

// serveCatalog lists items, or searches them when the path is /v1/search.
// The response is names and field names. It never contains a secret value.
func (s *Server) serveCatalog(w http.ResponseWriter, r *http.Request, agent string) {
	if !s.Vault.Unlocked() {
		contract.Write(w, contract.Rejected("", contract.CodeLocked))
		return
	}
	var (
		items []vault.CatalogItem
		err   error
	)
	if r.URL.Path == "/v1/search" {
		q := r.URL.Query().Get("q")
		if q == "" || len(q) > 200 {
			contract.Write(w, contract.Rejected("", contract.CodeBadRequest))
			return
		}
		items, err = s.Vault.Search(r.Context(), q)
	} else {
		items, err = s.Vault.List(r.Context())
	}
	if err != nil {
		contract.Write(w, contract.Rejected("", vaultCode(err)))
		return
	}
	if items == nil {
		items = []vault.CatalogItem{}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(catalogBody{Items: items})
	s.audit("listed", agent, slog.Int("count", len(items)))
}
