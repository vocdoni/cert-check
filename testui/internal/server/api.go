package server

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	certcheck "github.com/vocdoni/cert-check"
)

// Per-IP limits on the main listener (spec "Rate limiting"); newIPLimiter
// needs a positive rate.
const (
	createPerMinute = 20
	redeemPerMinute = 60
)

type apiError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

type providerJSON struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Beta        bool   `json:"beta"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v) // the client went away; nothing to do
}

func writeError(w http.ResponseWriter, status int, code string, retryable bool) {
	writeJSON(w, status, map[string]any{"status": "error", "error": apiError{Code: code, Message: message(code), Retryable: retryable}})
}

// handleProviders: GET /api/v1/providers.
func (a *App) handleProviders(w http.ResponseWriter, _ *http.Request) {
	out := make([]providerJSON, 0, len(a.providers))
	for _, p := range a.providers {
		info := p.Info()
		out = append(out, providerJSON{ID: info.ID, Name: info.Name, Description: info.Description, Beta: info.Beta})
	}
	writeJSON(w, http.StatusOK, out)
}

// handleCreate: POST /api/v1/transactions {"provider":"<id>"}.
func (a *App) handleCreate(w http.ResponseWriter, r *http.Request) {
	if st, code := postGuard(r, a.publicOrigin); st != 0 {
		writeError(w, st, code, false)
		return
	}
	logForwardedHeaders(r, a.log)
	if ok, wait := a.createLimiter.allow(clientIP(r, a.cfg.TrustedProxyHops), a.now()); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait/time.Second)+1))
		writeError(w, http.StatusTooManyRequests, "rate_limited", true)
		return
	}
	var body struct {
		Provider string `json:"provider"`
	}
	if !decodeJSON(w, r, &body) {
		writeError(w, http.StatusBadRequest, "bad_request", false)
		return
	}
	if !a.providerIDs[body.Provider] {
		writeError(w, http.StatusBadRequest, "unknown_provider", false)
		return
	}
	prev, _ := txCookie(r)
	cookie, state, expires, err := a.store.Create(body.Provider, prev)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "store_full", true)
		return
	}
	setTxCookie(w, cookie)
	authURL := "https://" + body.Provider + "." + a.cfg.AuthDomain + ":" + strconv.Itoa(a.cfg.AuthPublicPort) +
		authenticatePath + "?state=" + string(state)
	writeJSON(w, http.StatusCreated, map[string]string{"authUrl": authURL, "expiresAt": expires.UTC().Format(time.RFC3339)})
}

// handleRedeem: POST /api/v1/transactions/redeem {"code":"…"} with the cookie.
func (a *App) handleRedeem(w http.ResponseWriter, r *http.Request) {
	if st, code := postGuard(r, a.publicOrigin); st != 0 {
		writeError(w, st, code, false)
		return
	}
	if ok, wait := a.redeemLimiter.allow(clientIP(r, a.cfg.TrustedProxyHops), a.now()); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait/time.Second)+1))
		writeError(w, http.StatusTooManyRequests, "rate_limited", true)
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	if !decodeJSON(w, r, &body) {
		writeError(w, http.StatusBadRequest, "bad_request", false)
		return
	}
	// invalid answers 400 with minimal diagnostics and no identity data.
	invalid := func(technical string) {
		diag := certcheck.Diagnostics{DiagnosticID: certcheck.NewDiagnosticID(), Time: a.now().UTC(), ServerVersion: a.version,
			Code: "invalid_or_expired", TechnicalDetail: technical}
		a.log.Info("redeem rejected", "diagnosticId", diag.DiagnosticID, "reason", technical)
		writeJSON(w, http.StatusBadRequest, map[string]any{"status": "error",
			"error": apiError{Code: "invalid_or_expired", Message: message("invalid_or_expired")}, "diagnostics": diag})
	}
	cookie, ok := txCookie(r)
	if !ok {
		invalid("cookie_missing")
		return
	}
	o, err := a.store.Redeem(Secret(body.Code), cookie)
	switch {
	case errors.Is(err, ErrCookie):
		invalid("cookie_mismatch")
		return
	case err != nil:
		invalid("code_unknown_or_expired")
		return
	}
	clearTxCookie(w)
	if o.Err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"status": "error",
			"error":       apiError{Code: string(o.Err.Code), Message: message(string(o.Err.Code)), Retryable: o.Err.Retryable},
			"diagnostics": o.Err.Diagnostics})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "success", "result": o.Result})
}

// handleCurrent: GET /api/v1/transactions/current (cookie-bound).
func (a *App) handleCurrent(w http.ResponseWriter, r *http.Request) {
	snap := Snapshot{Status: TxNone}
	if c, ok := txCookie(r); ok {
		snap = a.store.Current(c)
	}
	out := map[string]any{"status": snap.Status, "provider": snap.Provider, "createdAt": nil,
		"authHost": "", "authPort": a.cfg.AuthPublicPort}
	if snap.Status != TxNone {
		out["createdAt"] = snap.CreatedAt.UTC().Format(time.RFC3339)
		out["authHost"] = snap.Provider + "." + a.cfg.AuthDomain
	}
	writeJSON(w, http.StatusOK, out)
}

// message is the single code → English message table.
func message(code string) string {
	if m, ok := messages[code]; ok {
		return m
	}
	return messages[string(certcheck.CodeInternal)]
}

var messages = map[string]string{
	string(certcheck.CodeNoCertificate):               "No certificate was presented.",
	string(certcheck.CodeProviderMismatch):            "The certificate belongs to a different provider than the one selected.",
	string(certcheck.CodeUntrustedIssuer):             "The certificate was not issued by a supported certification authority.",
	string(certcheck.CodeInvalidChain):                "The certificate chain could not be validated.",
	string(certcheck.CodeExpired):                     "The certificate has expired.",
	string(certcheck.CodeNotYetValid):                 "The certificate is not valid yet.",
	string(certcheck.CodeUnsupportedProfile):          "This type of certificate is not supported.",
	string(certcheck.CodeUnsupportedPurpose):          "The certificate cannot be used for authentication.",
	string(certcheck.CodeWeakAlgorithm):               "The certificate uses a key or signature algorithm that is too weak.",
	string(certcheck.CodeTestCertificate):             "This is a test or specimen certificate.",
	string(certcheck.CodeIdentityInvalid):             "The identity data in the certificate is not valid.",
	string(certcheck.CodeIdentityUnsupportedDocument): "This certificate identifies the holder with a document other than a Spanish DNI/NIE.",
	string(certcheck.CodeRevoked):                     "The certificate has been revoked or suspended.",
	string(certcheck.CodeRevocationUnknown):           "The certification authority does not recognise this certificate.",
	string(certcheck.CodeRevocationUnavailable):       "The revocation status could not be checked right now.",
	string(certcheck.CodeInternal):                    "Something went wrong on our side.",
	"invalid_or_expired":                              "This authentication link is no longer valid. Please start again.",
	"unknown_provider":                                "Unknown certificate provider.",
	"unsupported_media_type":                          "Unsupported request format.",
	"rate_limited":                                    "Too many attempts. Please wait a moment.",
	"store_full":                                      "The service is busy. Please try again shortly.",
	"forbidden":                                       "Request not allowed.",
	"bad_request":                                     "Malformed request.",
	"invalid_state":                                   "This authentication link is no longer valid. Please start again.",
}

// logForwardedHeaders records, at debug level, which client-address headers
// the platform edge sets and how many X-Forwarded-For entries arrive. Never
// the values. Used once at rollout to confirm the header (spec rate limiting).
func logForwardedHeaders(r *http.Request, log *slog.Logger) {
	if !log.Enabled(r.Context(), slog.LevelDebug) {
		return
	}
	var present []string
	for _, h := range []string{"X-Forwarded-For", "X-Real-IP", "X-Envoy-External-Address", "Forwarded"} {
		if r.Header.Get(h) != "" {
			present = append(present, h)
		}
	}
	entries := 0
	for _, v := range r.Header.Values("X-Forwarded-For") {
		for range strings.SplitSeq(v, ",") {
			entries++
		}
	}
	log.Debug("forwarded headers", "present", present, "xffEntries", entries)
}
