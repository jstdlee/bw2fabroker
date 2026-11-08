package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/jstdlee/bw2fabroker/internal/api"
	"github.com/jstdlee/bw2fabroker/internal/config"
)

// The admin socket is mode 0600 and owned by the broker user, so only that user (or root) can
// unlock the vault, clear the lockout, or resume an agent.

type adminRequest struct {
	Cmd      string `json:"cmd"`
	Password string `json:"password,omitempty"`
	Agent    string `json:"agent,omitempty"`
}

type adminResponse struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

func adminSocketPath() (string, error) {
	c, _, err := loadConfig()
	if err != nil {
		return "", err
	}
	return c.Admin.Socket, nil
}

func adminSimple(req adminRequest) error {
	path, err := adminSocketPath()
	if err != nil {
		return err
	}
	conn, err := net.DialTimeout("unix", path, 5*time.Second)
	if err != nil {
		return fmt.Errorf("cannot reach the running broker at %s: %w", path, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(90 * time.Second))
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return err
	}
	var resp adminResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return err
	}
	if !resp.OK {
		return errors.New(resp.Message)
	}
	fmt.Println(resp.Message)
	return nil
}

func listenAdmin(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	_ = os.Remove(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

func serveAdmin(ctx context.Context, l net.Listener, s *api.Server, cfg func() *config.Config) {
	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(90 * time.Second))
			var req adminRequest
			if err := json.NewDecoder(bufio.NewReader(c)).Decode(&req); err != nil {
				return
			}
			resp := handleAdmin(ctx, s, cfg, req)
			_ = json.NewEncoder(c).Encode(resp)
		}(conn)
	}
}

func handleAdmin(ctx context.Context, s *api.Server, cfg func() *config.Config, req adminRequest) adminResponse {
	switch req.Cmd {
	case "unlock":
		if err := s.UnlockVault(ctx, req.Password); err != nil {
			return adminResponse{Message: err.Error()}
		}
		return adminResponse{OK: true, Message: "Vault unlocked."}
	case "unlock-approvals":
		s.ClearApprovalLock()
		return adminResponse{OK: true, Message: "Approvals unlocked."}
	case "resume":
		if _, ok := cfg().Agents[req.Agent]; !ok {
			return adminResponse{Message: "no such agent"}
		}
		s.Resume(req.Agent)
		return adminResponse{OK: true, Message: "Agent resumed."}
	case "status":
		vaultState := "locked"
		if s.Vault.Unlocked() {
			vaultState = "unlocked"
		}
		approver := "down"
		if s.ApproverUp() {
			approver = "up"
		}
		msg := fmt.Sprintf("vault: %s\napprover listener: %s\napprovals locked: %v\npending requests: %d",
			vaultState, approver, s.ApprovalsLocked(), s.Store.Len())
		for _, n := range cfg().AgentNames() {
			if s.Suspended(n) {
				msg += "\nsuspended agent: " + n
			}
		}
		return adminResponse{OK: true, Message: msg}
	}
	return adminResponse{Message: "unknown admin command"}
}
