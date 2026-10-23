package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/store"
)

type auditContextKey struct{}
type auditOperation struct {
	id              int64
	action          string
	outcome, reason string
	startAttempted  bool
}

func (s *Server) listAuditEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Audit-Missed-Count", strconv.FormatUint(s.auditMissed.Load(), 10))
	if s.st == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"持久审计未装配"})
		return
	}
	q := r.URL.Query()
	limit, err := queryInt64(q.Get("limit"))
	if err != nil || limit < 0 || limit > 200 {
		s.writeErr(w, model.WrapValidation("审计分页大小无效"))
		return
	}
	after, err := queryInt64(q.Get("after_ms"))
	if err != nil {
		s.writeErr(w, model.WrapValidation("审计开始时间无效"))
		return
	}
	before, err := queryInt64(q.Get("before_ms"))
	if err != nil {
		s.writeErr(w, model.WrapValidation("审计结束时间无效"))
		return
	}
	page, err := s.st.ListAuditEventsPage(r.Context(), model.AuditEventFilter{
		PageRequest: model.PageRequest{Cursor: q.Get("cursor"), Limit: int(limit)},
		Category:    q.Get("category"), Action: q.Get("action"), Outcome: q.Get("outcome"),
		ResourceType: q.Get("resource_type"), ResourceID: q.Get("resource_id"), AfterMS: after, BeforeMS: before,
	})
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) auditActor(r *http.Request) string {
	identity := "bearer-admin"
	if s.sessionOK(r) {
		cookie, _ := r.Cookie(sessionCookie)
		identity = "cookie:" + cookie.Value
	} else if r.URL.Path == "/admin/api/login" || r.URL.Path == "/admin/api/logout" {
		identity = "session-request"
	}
	sum := sha256.Sum256([]byte("relay-gate:audit-actor:v1:" + identity))
	return hex.EncodeToString(sum[:])
}

func (s *Server) auditAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		action, resourceID, sensitiveRead := auditRequestAction(r)
		if action == "" {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		if s.st == nil {
			writeJSON(w, http.StatusServiceUnavailable, errBody{"持久审计未装配，操作未执行"})
			return
		}
		operation := &auditOperation{action: action}
		r = r.WithContext(context.WithValue(r.Context(), auditContextKey{}, operation))
		// Master rotation must close admission and drain accepted writes before
		// waiting on SQLite. Its handler begins audit before touching any key.
		if action != "master_rotate" {
			if err := s.startAuditOperation(r, r.Context(), resourceID); err != nil {
				s.auditUnavailable(w, action, "begin")
				writeJSON(w, http.StatusServiceUnavailable, errBody{"审计暂不可用，操作未执行"})
				return
			}
		}
		response := &auditResponseWriter{ResponseWriter: w, server: s, request: r, operation: operation, sensitiveRead: sensitiveRead}
		next.ServeHTTP(response, r)
		if !response.wroteHeader {
			response.WriteHeader(http.StatusOK)
		}
	})
}

type auditResponseWriter struct {
	http.ResponseWriter
	server        *Server
	request       *http.Request
	operation     *auditOperation
	sensitiveRead bool
	wroteHeader   bool
	blocked       bool
}

func (w *auditResponseWriter) WriteHeader(status int) {
	if w.wroteHeader || status < 200 {
		return
	}
	w.wroteHeader = true
	outcome, reason := w.operation.outcome, w.operation.reason
	if outcome == "" {
		outcome, reason = auditHTTPResult(status)
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(w.request.Context()), 3*time.Second)
	defer cancel()
	err := w.server.startAuditOperation(w.request, ctx, "current")
	if err == nil {
		err = w.server.st.CompleteAuditAction(ctx, w.operation.id, w.operation.action, outcome, reason)
	}
	if err != nil {
		w.server.auditUnavailable(w.ResponseWriter, w.operation.action, "complete")
		w.Header().Set("X-Audit-Status", "pending")
		if w.operation.id > 0 {
			w.Header().Set("X-Audit-Event-ID", strconv.FormatInt(w.operation.id, 10))
		} else {
			w.Header().Set("X-Audit-Status", "unavailable")
		}
		if w.sensitiveRead && status < 400 {
			w.blocked = true
			if w.server.creds != nil {
				w.server.creds.ClearMasterReveal()
			}
			w.Header().Del("Content-Length")
			writeJSON(w.ResponseWriter, http.StatusServiceUnavailable, errBody{"审计确认失败，敏感内容未返回"})
			return
		}
	}
	w.ResponseWriter.WriteHeader(status)
}

func (s *Server) startAuditOperation(r *http.Request, ctx context.Context, resourceID string) error {
	operation, _ := r.Context().Value(auditContextKey{}).(*auditOperation)
	if operation == nil {
		return errors.New("audit operation missing")
	}
	if operation.id > 0 {
		return nil
	}
	if operation.startAttempted {
		return errors.New("audit begin unavailable")
	}
	operation.startAttempted = true
	id, err := s.st.BeginAuditEvent(ctx, operation.action, resourceID, s.auditActor(r))
	operation.id = id
	return err
}

func (s *Server) auditUnavailable(w http.ResponseWriter, action, phase string) {
	missed := s.auditMissed.Add(1)
	w.Header().Set("X-Audit-Status", "unavailable")
	w.Header().Set("X-Audit-Missed-Count", strconv.FormatUint(missed, 10))
	if s.log != nil {
		s.log.Warn("管理审计写入不可用", "action", action, "phase", phase, "audit_missed_count", missed)
	}
}

// Rejected admission must not wait behind an accepted write and prevent the
// rotation's drain from progressing. There is no second queue or retry worker.
func (s *Server) writeAuditedRejection(w http.ResponseWriter, r *http.Request, status int, payload any) {
	action, resourceID, _ := auditRequestAction(r)
	if action != "" && s.st != nil {
		w.Header().Set("Cache-Control", "no-store")
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 100*time.Millisecond)
		defer cancel()
		id, err := s.st.BeginAuditEvent(ctx, action, resourceID, s.auditActor(r))
		if err == nil {
			outcome, reason := auditHTTPResult(status)
			err = s.st.CompleteAuditEvent(ctx, id, outcome, reason)
		}
		if err != nil {
			s.auditUnavailable(w, action, "admission_rejected")
			if id > 0 {
				w.Header().Set("X-Audit-Status", "pending")
				w.Header().Set("X-Audit-Event-ID", strconv.FormatInt(id, 10))
			}
		}
	}
	writeJSON(w, status, payload)
}

func (w *auditResponseWriter) Write(value []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.blocked {
		return 0, store.ErrAuditUnavailable
	}
	return w.ResponseWriter.Write(value)
}

func auditHTTPResult(status int) (string, string) {
	if status < 400 {
		return "succeeded", ""
	}
	reason := "operation_failed"
	switch status {
	case 400, 422:
		reason = "validation"
	case 401:
		reason = "unauthorized"
	case 403:
		reason = "forbidden"
	case 404:
		reason = "not_found"
	case 409:
		reason = "conflict"
	case 503:
		reason = "unavailable"
	}
	return "failed", reason
}

func setAuditAction(r *http.Request, action string) {
	if operation, _ := r.Context().Value(auditContextKey{}).(*auditOperation); operation != nil {
		operation.action = action
	}
}

func setAuditResult(r *http.Request, outcome, reason string) {
	if operation, _ := r.Context().Value(auditContextKey{}).(*auditOperation); operation != nil {
		operation.outcome, operation.reason = outcome, reason
	}
}

func (s *Server) recordAuditStep(r *http.Request, action string) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 3*time.Second)
	defer cancel()
	id, err := s.st.BeginAuditEvent(ctx, action, "current", s.auditActor(r))
	if err != nil {
		return err
	}
	return s.st.CompleteAuditEvent(ctx, id, "succeeded", "")
}

// Existing activation-pending responses explicitly distinguish a committed
// mutation from a failed one. Consume that fact without storing its payload.
func (w *auditResponseWriter) auditPayload(payload any) {
	if data, ok := payload.(map[string]any); ok && data["persisted"] == true {
		w.operation.outcome, w.operation.reason = "succeeded", "activation_pending"
	}
	if w.operation.action == "recipe_test" || w.operation.action == "profile_test_activate" {
		if execution, ok := payload.(model.ProbeExecution); ok && !execution.Success {
			w.operation.outcome, w.operation.reason = "failed", "operation_failed"
		}
	}
}

// Match only fixed management routes. Raw path text, query values and bodies
// never become action codes, resource types, actor identity or audit details.
func auditRequestAction(r *http.Request) (action, resourceID string, sensitiveRead bool) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/admin/api/"), "/")
	if len(parts) == 0 {
		return
	}
	if len(parts) > 1 {
		if id, err := strconv.ParseInt(parts[1], 10, 64); err == nil && id > 0 {
			resourceID = strconv.FormatInt(id, 10)
		}
	}
	if len(parts) == 1 {
		switch {
		case parts[0] == "login" && r.Method == "POST":
			action = "session_login"
		case parts[0] == "logout" && r.Method == "POST":
			action = "session_logout"
		case parts[0] == "settings" && r.Method == "PUT":
			action = "settings_update"
		case parts[0] == "state" && r.Method == "POST":
			action = "state_change"
		case parts[0] == "request-logs" && r.Method == "DELETE":
			action = "request_logs_clear"
		case parts[0] == "samples" && r.Method == "DELETE":
			action = "sample_bulk_delete"
		case parts[0] == "calibrations" && r.Method == "POST":
			action = "calibration_create"
		}
	}
	if parts[0] == "credentials" && len(parts) == 2 && r.Method == "POST" {
		action = map[string]string{"reveal-master": "master_reveal", "reveal-relay": "relay_reveal", "rotate-relay": "relay_rotate", "revoke-relay-grace": "relay_revoke_grace", "reset-admin": "admin_reset", "rotate-master": "master_rotate"}[parts[1]]
		return action, "current", parts[1] == "reveal-master" || parts[1] == "reveal-relay"
	}
	if parts[0] == "samples" {
		if len(parts) == 2 && r.Method == "GET" || len(parts) == 3 && parts[2] == "view" && r.Method == "POST" {
			return "sample_view", resourceID, true
		}
		if len(parts) == 3 && parts[2] == "pin" && r.Method == "POST" {
			return "sample_pin", resourceID, false
		}
	}
	if (len(parts) == 1 && r.Method == "POST") || len(parts) == 2 {
		prefix := map[string]string{"upstreams": "upstream", "model-names": "model", "routes": "route", "upstream-endpoints": "endpoint", "probe-secrets": "secret", "probe-recipes": "recipe", "transforms": "transform"}[parts[0]]
		if prefix != "" {
			suffix := map[string]string{"POST": "create", "PUT": "update", "DELETE": "delete"}[r.Method]
			if suffix != "" {
				candidate := prefix + "_" + suffix
				if _, ok := model.AuditActionSpec(candidate); ok {
					action = candidate
				}
			}
		}
	}
	if len(parts) >= 2 && parts[0] == "security" {
		if len(parts) == 4 && parts[1] == "findings" && parts[3] == "review" && r.Method == "PUT" {
			action = "security_finding_review"
			sum := sha256.Sum256([]byte("security-finding:" + parts[2]))
			resourceID = "finding-" + hex.EncodeToString(sum[:])
		} else if parts[1] == "ignore-rules" {
			if len(parts) == 2 && r.Method == "POST" {
				action = "security_ignore_create"
			} else if len(parts) == 3 {
				action = map[string]string{"PUT": "security_ignore_update", "DELETE": "security_ignore_delete"}[r.Method]
				if id, err := strconv.ParseInt(parts[2], 10, 64); err == nil && id > 0 {
					resourceID = strconv.FormatInt(id, 10)
				}
			}
		} else if len(parts) == 2 && r.Method == "POST" {
			action = map[string]string{"scan": "security_scan", "canary": "security_canary"}[parts[1]]
		} else if parts[1] == "smtp" {
			if len(parts) == 2 && r.Method == "PUT" {
				action = "smtp_update"
			} else if len(parts) == 3 && parts[2] == "test" && r.Method == "POST" {
				action = "smtp_test"
			}
		} else if len(parts) == 4 && parts[1] == "findings" && parts[3] == "evidence" && r.Method == "POST" {
			sum := sha256.Sum256([]byte("security-finding:" + parts[2]))
			resourceID = "finding-" + hex.EncodeToString(sum[:])
			action, sensitiveRead = "security_evidence_view", true
		}
	}
	if len(parts) == 3 {
		switch {
		case parts[0] == "routes" && parts[2] == "probe" && r.Method == "POST":
			action = "route_probe"
		case parts[0] == "upstream-endpoints" && parts[2] == "confirm-review" && r.Method == "POST":
			action = "endpoint_confirm_review"
		case parts[0] == "probe-recipes" && r.Method == "POST":
			action = map[string]string{"versions": "recipe_version_create", "disable": "recipe_disable", "archive": "recipe_archive"}[parts[2]]
		case parts[0] == "probe-recipe-versions" && parts[2] == "test" && r.Method == "POST":
			action = "recipe_test"
		case parts[0] == "client-probe-profiles" && r.Method == "POST":
			action = map[string]string{"test": "profile_test_activate", "disable": "profile_disable"}[parts[2]]
		case parts[0] == "calibrations" && r.Method == "POST":
			action = map[string]string{"start": "calibration_start", "cancel": "calibration_cancel"}[parts[2]]
		case parts[0] == "transforms":
			if parts[2] == "draft" && r.Method == "PUT" {
				action = "transform_draft_update"
			} else if r.Method == "POST" {
				action = map[string]string{"publish": "transform_publish", "shadow": "transform_shadow"}[parts[2]]
			}
		}
	}
	if len(parts) == 5 && parts[0] == "probe-recipes" && parts[2] == "versions" && parts[4] == "publish" && r.Method == "POST" {
		action = "recipe_publish"
	}
	if len(parts) == 2 && parts[0] == "transforms" {
		if parts[1] == "rollback" && r.Method == "POST" {
			action = "transform_rollback"
		} else if parts[1] == "budgets" && r.Method == "PUT" {
			action = "transform_budget_update"
		}
	}
	return
}
