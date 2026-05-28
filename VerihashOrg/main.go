package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	_ "modernc.org/sqlite"
)

type PublishCredentialRequest struct {
	DID       string          `json:"did" binding:"required"`
	Timestamp string          `json:"timestamp" binding:"required"`
	Nonce     string          `json:"nonce" binding:"required"`
	Payload   json.RawMessage `json:"payload" binding:"required"`
	Signature string          `json:"signature" binding:"required"`
}

type PublicCredentialPayload struct {
	DocumentType   string   `json:"document_type"`
	SchemaVersion  string   `json:"schema_version"`
	VCID           string   `json:"vc_id"`
	Issuer         string   `json:"issuer"`
	IssuedAt       string   `json:"issued_at"`
	Title          string   `json:"title,omitempty"`
	AIInsight      string   `json:"ai_insight,omitempty"`
	AIEngine       string   `json:"ai_engine,omitempty"`
	SkillTags      []string `json:"skill_tags,omitempty"`
	VCHash         string   `json:"vc_hash"`
	PrevVCHash     string   `json:"prev_vc_hash,omitempty"`
	ProofSignature string   `json:"proof_signature"`
}

type ProfilePayload struct {
	Name    string            `json:"name,omitempty"`
	Website string            `json:"website,omitempty"`
	Custom  map[string]string `json:"custom,omitempty"`
}

var db *sql.DB

type IPRateLimiter struct {
	mu      sync.Mutex
	history map[string][]time.Time
}

func NewIPRateLimiter() *IPRateLimiter {
	return &IPRateLimiter{
		history: make(map[string][]time.Time),
	}
}

func (l *IPRateLimiter) Allow(ip string, limit int, window time.Duration) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-window)

	var valid []time.Time
	for _, t := range l.history[ip] {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}

	if len(valid) >= limit {
		l.history[ip] = valid
		return false
	}

	valid = append(valid, now)
	l.history[ip] = valid
	return true
}

var ipLimiter = NewIPRateLimiter()

func initDB() {
	dbDir := "./data"
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		log.Fatalf("Failed to create data directory: %v", err)
	}

	var err error
	db, err = sql.Open("sqlite", filepath.Join(dbDir, "verihash.db"))
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}

	schema := `
	CREATE TABLE IF NOT EXISTS credentials (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		did TEXT NOT NULL,
		vc_id TEXT NOT NULL,
		payload_json TEXT NOT NULL,
		vc_hash TEXT NOT NULL,
		prev_vc_hash TEXT DEFAULT '',
		signature TEXT NOT NULL,
		status TEXT NOT NULL DEFAULT 'active',
		issued_at TEXT NOT NULL,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL,
		UNIQUE(did, vc_id)
	);

	CREATE TABLE IF NOT EXISTS nonces (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		did TEXT NOT NULL,
		nonce TEXT NOT NULL,
		created_at TEXT NOT NULL,
		UNIQUE(did, nonce)
	);

	CREATE TABLE IF NOT EXISTS revocations (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		did TEXT NOT NULL,
		vc_id TEXT NOT NULL,
		revoke_json TEXT NOT NULL,
		revoked_at TEXT NOT NULL,
		created_at TEXT NOT NULL,
		UNIQUE(did, vc_id)
	);

	CREATE TABLE IF NOT EXISTS profiles (
		did TEXT PRIMARY KEY,
		profile_json TEXT NOT NULL,
		updated_at TEXT NOT NULL
	);
	`

	_, err = db.Exec(schema)
	if err != nil {
		log.Fatalf("Failed to initialize database schema: %v", err)
	}
	log.Println("Database initialized successfully.")
}

func handlePostCredential(c *gin.Context) {
	var req PublishCredentialRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "detail": err.Error()})
		return
	}

	// 1. timestamp replay prevention
	ts, err := time.Parse(time.RFC3339, req.Timestamp)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_timestamp"})
		return
	}

	if time.Since(ts) > 10*time.Minute || time.Until(ts) > 2*time.Minute {
		c.JSON(http.StatusBadRequest, gin.H{"error": "timestamp_out_of_range"})
		return
	}

	// 2. payload size limit (100KB)
	if len(req.Payload) > 100*1024 {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "payload_too_large"})
		return
	}

	// 3. parse payload
	var payload PublicCredentialPayload
	if err := json.Unmarshal(req.Payload, &payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_payload_json"})
		return
	}

	// 4. basic schema validation
	if payload.VCID == "" || payload.VCHash == "" || payload.IssuedAt == "" || payload.ProofSignature == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing_required_payload_fields"})
		return
	}

	if payload.Issuer != req.DID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "issuer_did_mismatch"})
		return
	}

	// 5. verify upload request signature
	if err := verifyPublishSignature(req.DID, req.Timestamp, req.Nonce, req.Payload, req.Signature); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_signature", "detail": err.Error()})
		return
	}

	// 5b. 24-hour upload quota validation (accept max 20 new credentials per day)
	var past24hCount int
	time24hAgo := time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339)
	err = db.QueryRow(`
		SELECT COUNT(*) FROM credentials 
		WHERE did = ? AND created_at >= ?
	`, req.DID, time24hAgo).Scan(&past24hCount)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "rate_limit_check_failed"})
		return
	}
	if past24hCount >= 20 {
		c.JSON(http.StatusTooManyRequests, gin.H{
			"error": "rate_limit_exceeded",
			"detail": "Daily upload limit exceeded. Maximum of 20 credentials per 24 hours per identity.",
		})
		return
	}

	now := time.Now().UTC().Format(time.RFC3339)

	tx, err := db.Begin()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db_begin_failed"})
		return
	}
	defer tx.Rollback()

	// 6. nonce deduplication
	_, err = tx.Exec(
		`INSERT INTO nonces (did, nonce, created_at) VALUES (?, ?, ?)`,
		req.DID, req.Nonce, now,
	)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "duplicate_nonce_or_replay"})
		return
	}

	// 7. Credential database storage (UPSERT)
	_, err = tx.Exec(`
		INSERT INTO credentials (
			did, vc_id, payload_json, vc_hash, prev_vc_hash,
			signature, status, issued_at, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)
		ON CONFLICT(did, vc_id) DO UPDATE SET
			payload_json = excluded.payload_json,
			vc_hash = excluded.vc_hash,
			prev_vc_hash = excluded.prev_vc_hash,
			signature = excluded.signature,
			status = 'active',
			issued_at = excluded.issued_at,
			updated_at = excluded.updated_at
	`,
		req.DID,
		payload.VCID,
		string(req.Payload),
		payload.VCHash,
		payload.PrevVCHash,
		payload.ProofSignature,
		payload.IssuedAt,
		now,
		now,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "insert_credential_failed", "detail": err.Error()})
		return
	}

	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db_commit_failed"})
		return
	}

	strippedDID := strings.TrimPrefix(req.DID, "did:key:")
	c.JSON(http.StatusOK, gin.H{
		"status": "ok",
		"did":    req.DID,
		"vc_id":  payload.VCID,
		"url":    fmt.Sprintf("/u/%s/credentials/%s.json", url.PathEscape(strippedDID), url.PathEscape(payload.VCID)),
	})
}

func handlePostRevoke(c *gin.Context) {
	var req PublishCredentialRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "detail": err.Error()})
		return
	}

	// 1. timestamp replay prevention
	ts, err := time.Parse(time.RFC3339, req.Timestamp)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_timestamp"})
		return
	}
	if time.Since(ts) > 10*time.Minute || time.Until(ts) > 2*time.Minute {
		c.JSON(http.StatusBadRequest, gin.H{"error": "timestamp_out_of_range"})
		return
	}

	// 2. parse payload (Tombstone)
	var tombstone struct {
		VCID            string `json:"vc_id"`
		IssuerDID       string `json:"issuer_did"`
		RevokedAt       string `json:"revoked_at"`
		RevokeSignature string `json:"revoke_signature"`
		OriginalVCHash  string `json:"original_vc_hash"`
		PrevVCHash      string `json:"prev_vc_hash"`
		TombstoneType   string `json:"tombstone_type"` // "destroy" | "withdraw"
	}
	if err := json.Unmarshal(req.Payload, &tombstone); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_tombstone_json"})
		return
	}

	// 3. basic validation
	if tombstone.VCID == "" || tombstone.IssuerDID == "" || tombstone.RevokedAt == "" || tombstone.RevokeSignature == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing_required_tombstone_fields"})
		return
	}
	if tombstone.IssuerDID != req.DID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "issuer_did_mismatch"})
		return
	}

	// 4. verify upload request signature
	if err := verifyPublishSignature(req.DID, req.Timestamp, req.Nonce, req.Payload, req.Signature); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_signature", "detail": err.Error()})
		return
	}

	now := time.Now().UTC().Format(time.RFC3339)

	tx, err := db.Begin()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db_begin_failed"})
		return
	}
	defer tx.Rollback()

	// 5. nonce deduplication
	_, err = tx.Exec(`INSERT INTO nonces (did, nonce, created_at) VALUES (?, ?, ?)`, req.DID, req.Nonce, now)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "duplicate_nonce_or_replay"})
		return
	}

	// 6. UPSERT credential block to maintain hash chain continuity.
	//    • tombstone_type="destroy"  → status='destroyed'  (credential permanently destroyed)
	//    • tombstone_type="withdraw" → status='withdrawn'  (user withdrew publication, local copy preserved)
	//    • legacy data fallback (no tombstone_type) -> default 'destroyed'
	dbStatus := "destroyed"
	if tombstone.TombstoneType == "withdraw" {
		dbStatus = "withdrawn"
	}
	_, err = tx.Exec(`
		INSERT INTO credentials (
			did, vc_id, payload_json, vc_hash, prev_vc_hash,
			signature, status, issued_at, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(did, vc_id) DO UPDATE SET
			payload_json = excluded.payload_json,
			vc_hash      = excluded.vc_hash,
			prev_vc_hash = excluded.prev_vc_hash,
			status       = excluded.status,
			updated_at   = excluded.updated_at
	`, req.DID, tombstone.VCID,
		string(req.Payload),
		tombstone.OriginalVCHash,
		tombstone.PrevVCHash,
		tombstone.RevokeSignature,
		dbStatus,
		tombstone.RevokedAt,
		now, now,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "update_credential_failed"})
		return
	}

	// 7. insert revocation record
	_, err = tx.Exec(`
		INSERT INTO revocations (did, vc_id, revoke_json, revoked_at, created_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(did, vc_id) DO UPDATE SET
			revoke_json = excluded.revoke_json,
			revoked_at = excluded.revoked_at
	`, req.DID, tombstone.VCID, string(req.Payload), tombstone.RevokedAt, now)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "insert_revocation_failed"})
		return
	}

	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db_commit_failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status": "revoked",
		"did":    req.DID,
		"vc_id":  tombstone.VCID,
	})
}

func handlePostProfile(c *gin.Context) {
	var req PublishCredentialRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "detail": err.Error()})
		return
	}

	// 1. timestamp replay prevention
	ts, err := time.Parse(time.RFC3339, req.Timestamp)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_timestamp"})
		return
	}

	if time.Since(ts) > 10*time.Minute || time.Until(ts) > 2*time.Minute {
		c.JSON(http.StatusBadRequest, gin.H{"error": "timestamp_out_of_range"})
		return
	}

	// 2. payload size limit (50KB)
	if len(req.Payload) > 50*1024 {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "payload_too_large"})
		return
	}

	// 3. parse payload (ProfilePayload)
	var payload ProfilePayload
	if err := json.Unmarshal(req.Payload, &payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_profile_json"})
		return
	}

	// 4. verify signature
	if err := verifyPublishSignature(req.DID, req.Timestamp, req.Nonce, req.Payload, req.Signature); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_signature", "detail": err.Error()})
		return
	}

	now := time.Now().UTC().Format(time.RFC3339)

	tx, err := db.Begin()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db_begin_failed"})
		return
	}
	defer tx.Rollback()

	// 5. nonce deduplication
	_, err = tx.Exec(
		`INSERT INTO nonces (did, nonce, created_at) VALUES (?, ?, ?)`,
		req.DID, req.Nonce, now,
	)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "duplicate_nonce_or_replay"})
		return
	}

	// 6. Profile database storage (UPSERT)
	_, err = tx.Exec(`
		INSERT INTO profiles (
			did, profile_json, updated_at
		) VALUES (?, ?, ?)
		ON CONFLICT(did) DO UPDATE SET
			profile_json = excluded.profile_json,
			updated_at = excluded.updated_at
	`,
		req.DID,
		string(req.Payload),
		now,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "insert_profile_failed", "detail": err.Error()})
		return
	}

	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db_commit_failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status": "ok",
		"did":    req.DID,
	})
}

func RateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == "POST" {
			ip := c.ClientIP()
			// Normal human manual actions: limit to maximum of 3 operations per minute per IP
			if !ipLimiter.Allow(ip, 3, time.Minute) {
				c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
					"error":  "rate_limit_exceeded",
					"detail": "Upload speed limit exceeded. Maximum 3 actions per minute. Please try again later.",
				})
				return
			}
		}
		c.Next()
	}
}

func main() {
	initDB()
	defer db.Close()

	r := gin.Default()

	r.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "pong"})
	})

	v1 := r.Group("/v1")
	v1.Use(RateLimitMiddleware())
	{
		v1.POST("/credentials", handlePostCredential)
		v1.POST("/revoke", handlePostRevoke)
		v1.POST("/profile", handlePostProfile)
		v1.DELETE("/credentials/:vc_id", func(c *gin.Context) {
			c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
		})
	}

	r.GET("/", func(c *gin.Context) {
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VeriHash.org — AI-Native Public Gateway for Work Credentials</title>
  <meta name="description" content="VeriHash.org is a lightweight, machine-readable public node for VeriHash credentials, designed for AI systems, search engines, and future agents.">
  <style>
    :root {
      --bg-color: #0b0e14;
      --text-color: #c0d0e0;
      --font-family: 'Courier New', Courier, monospace;
      --border-color: rgba(0,255,204,0.15);
      --logo-color: #00ffcc;
      --logo-slash: rgba(0,255,204,0.35);
      --tagline-color: rgba(0,255,204,0.5);
      --intro-lead-color: #e0eaf4;
      --intro-lead-border: #00ffcc;
      --section-label-color: rgba(0,255,204,0.55);
      --desc-color: #a0b4c8;
      --divider-color: rgba(0,255,204,0.2);
      --step-num-color: #00ffcc;
      --step-num-border: rgba(0,255,204,0.4);
      --cta-btn-color: #00ffcc;
      --cta-btn-border: #00ffcc;
      --cta-btn-hover-bg: rgba(0,255,204,0.12);
      --footer-border: rgba(255,255,255,0.07);
      --notice-color: rgba(160,180,200,0.5);
      --notice-prefix-color: rgba(0,255,204,0.35);
      --link-color: #00ffcc;
      --link-border: rgba(0,255,204,0.35);
    }

    body.theme-light {
      --bg-color: #f8fafc;
      --text-color: #1e293b;
      --font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      --border-color: #e2e8f0;
      --logo-color: #0f172a;
      --logo-slash: #64748b;
      --tagline-color: #64748b;
      --intro-lead-color: #0f172a;
      --intro-lead-border: #0284c7;
      --section-label-color: #0284c7;
      --desc-color: #334155;
      --divider-color: #e2e8f0;
      --step-num-color: #0284c7;
      --step-num-border: #0284c7;
      --cta-btn-color: #0284c7;
      --cta-btn-border: #0284c7;
      --cta-btn-hover-bg: rgba(2, 132, 199, 0.08);
      --footer-border: #e2e8f0;
      --notice-color: #64748b;
      --notice-prefix-color: #dc2626;
      --link-color: #0284c7;
      --link-border: rgba(2, 132, 199, 0.35);
    }

    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg-color);
      color: var(--text-color);
      font-family: var(--font-family);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      transition: background 0.25s, color 0.25s;
    }
    .page-wrap {
      width: 100%;
      max-width: 760px;
      padding: 3rem 2rem 2rem;
      flex: 1;
    }
    /* ── Header ── */
    .site-header {
      display: flex;
      align-items: baseline;
      gap: 0.75rem;
      margin-bottom: 2.5rem;
      border-bottom: 1px solid var(--border-color);
      padding-bottom: 1.5rem;
    }
    .logo {
      font-size: 1.5rem;
      font-weight: bold;
      color: var(--logo-color);
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }
    .logo-slash { color: var(--logo-slash); }
    .tagline {
      font-size: 0.8rem;
      color: var(--tagline-color);
      letter-spacing: 0.05em;
      text-transform: uppercase;
    }
    /* ── Intro ── */
    .intro-lead {
      font-size: 1rem;
      color: var(--intro-lead-color);
      line-height: 1.75;
      margin-bottom: 1.25rem;
      border-left: 3px solid var(--intro-lead-border);
      padding-left: 1rem;
    }
    /* ── Section ── */
    .section { margin-bottom: 2.25rem; }
    .section-label {
      font-size: 0.72rem;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      color: var(--section-label-color);
      margin-bottom: 0.75rem;
    }
    .section-label::before { content: "// "; }
    p {
      font-size: 0.88rem;
      line-height: 1.85;
      color: var(--desc-color);
      margin-bottom: 0.85rem;
    }
    /* ── Divider ── */
    .divider {
      border: none;
      border-top: 1px dashed var(--divider-color);
      margin: 2rem 0;
    }
    body.theme-light .divider {
      border-top: 1px solid var(--divider-color);
    }
    /* ── How-to steps ── */
    .steps { list-style: none; display: flex; flex-direction: column; gap: 0.9rem; }
    .steps li {
      display: flex;
      gap: 0.85rem;
      font-size: 0.87rem;
      line-height: 1.7;
      color: var(--desc-color);
    }
    .step-num {
      flex-shrink: 0;
      width: 1.6rem;
      height: 1.6rem;
      border: 1px solid var(--step-num-border);
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 0.72rem;
      color: var(--step-num-color);
      margin-top: 0.15rem;
    }
    /* ── CTA Button ── */
    .cta-wrap { margin: 1.5rem 0 0.5rem; }
    .cta-btn {
      display: inline-block;
      padding: 0.6rem 1.25rem;
      border: 1px solid var(--cta-btn-border);
      color: var(--cta-btn-color);
      text-decoration: none;
      font-size: 0.82rem;
      letter-spacing: 0.06em;
      text-transform: uppercase;
      transition: background 0.2s, color 0.2s;
    }
    .cta-btn:hover { background: var(--cta-btn-hover-bg); }
    /* ── Footer notice ── */
    footer {
      width: 100%;
      max-width: 760px;
      padding: 1.25rem 2rem 2rem;
      border-top: 1px solid var(--footer-border);
    }
    .notice {
      font-size: 0.75rem;
      color: var(--notice-color);
      line-height: 1.7;
    }
    .notice::before {
      content: "⚠ ";
      color: var(--notice-prefix-color);
    }
    a { color: var(--link-color); text-decoration: none; border-bottom: 1px dashed var(--link-border); }
    a:hover { border-bottom-style: solid; }

    .theme-switch {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        background: rgba(0, 255, 204, 0.08);
        border: 1px solid rgba(0, 255, 204, 0.3);
        color: #00ffcc;
        font-size: 0.7rem;
        font-family: monospace;
        padding: 4px 10px;
        border-radius: 4px;
        cursor: pointer;
        transition: all 0.2s ease;
        text-decoration: none;
        letter-spacing: 0.05em;
    }
    .theme-switch:hover {
        background: rgba(0, 255, 204, 0.2);
        color: #fff;
        border-color: #00ffcc;
    }
    body.theme-light .theme-switch {
        background: rgba(2, 132, 199, 0.08);
        border: 1px solid rgba(2, 132, 199, 0.3);
        color: #0284c7;
    }
    body.theme-light .theme-switch:hover {
        background: #0284c7;
        color: #fff;
    }
  </style>
</head>
<body>
  <div class="page-wrap">
    <div style="display: flex; justify-content: flex-end; margin-bottom: 1.5rem;">
      <button id="theme-toggle-btn" class="theme-switch">🌓 LIGHT MODE</button>
    </div>

    <header class="site-header">
      <div class="logo">_VERIHASH<span class="logo-slash">/</span>ORG</div>
      <div class="tagline">AI-Native Public Gateway for Work Credentials</div>
    </header>

    <div class="section">
      <p class="intro-lead">
        VeriHash.org provides a lightweight, machine-readable public node for VeriHash credentials.
        It is designed for AI systems, search engines, and future agents to discover and understand
        structured evidence of professional work.
      </p>
      <p>
        VeriHash does not host raw files, private documents, or local working materials.
        It only accepts sanitized, text-based public credential payloads generated by the VeriHash desktop application.
      </p>
      <p>
        Each published credential is signed by the user's local identity key and linked to a long-term
        personal work chain. The goal is not to prove that a person is excellent, but to preserve a
        verifiable trail of what the person has actually worked on over time.
      </p>
      <p>
        For human visitors, this website offers a simple view of public VeriHash profiles.
        For AI systems, it provides structured JSON, public indexes, and <code>llms.txt</code> entries
        optimized for machine reading.
      </p>
      <p>
        VeriHash.org is an optional public relay and resolver. Users may also publish their credentials
        through GitHub Gist, their own websites, or other self-hosted channels.
      </p>
    </div>

    <hr class="divider">

    <div class="section">
      <div class="section-label">How to Use VeriHash</div>
      <p>
        To publish your own VeriHash work credentials, download the open-source VeriHash desktop
        application from GitHub Releases:
      </p>
      <div class="cta-wrap">
        <a class="cta-btn" href="https://github.com/briansuin/verihash/releases" target="_blank">
          [ Download VeriHash Desktop ↗ ]
        </a>
      </div>
      <br>
      <ul class="steps">
        <li>
          <div class="step-num">1</div>
          <span>After installation, all operations are completed inside the desktop application.
          Users do not need to register, log in, or manage an account on VeriHash.org.</span>
        </li>
        <li>
          <div class="step-num">2</div>
          <span>Create credentials locally in the desktop application and choose
          <strong style="color: var(--text-color); font-weight: bold;">VeriHash.org</strong> as a broadcast channel.</span>
        </li>
        <li>
          <div class="step-num">3</div>
          <span>Only sanitized public credential payloads are uploaded. Raw files, private documents,
          local paths, and original working materials remain on your machine.</span>
        </li>
      </ul>
    </div>

  </div>

  <footer>
    <p class="notice">
      VeriHash.org only stores public credential payloads intentionally published by users.
      Please do not publish confidential client materials, private documents, personal information,
      local file paths, API keys, or any unlawful content.
    </p>
  </footer>

  <script>
    const urlParams = new URLSearchParams(window.location.search);
    const themeParam = urlParams.get('theme');
    const savedTheme = localStorage.getItem('verihash-theme-preference');
    const body = document.body;
    const btn = document.getElementById('theme-toggle-btn');

    function setTheme(isLight) {
        if (isLight) {
            body.classList.add('theme-light');
            if (btn) btn.innerHTML = '🌓 DARK MODE';
        } else {
            body.classList.remove('theme-light');
            if (btn) btn.innerHTML = '🌓 LIGHT MODE';
        }
    }

    const isLight = themeParam === 'light' || (!themeParam && savedTheme === 'light');
    setTheme(isLight);

    if (btn) {
        btn.addEventListener('click', () => {
            const nowLight = !body.classList.contains('theme-light');
            setTheme(nowLight);
            localStorage.setItem('verihash-theme-preference', nowLight ? 'light' : 'dark');
        });
    }
  </script>
</body>
</html>`))
	})

	r.GET("/robots.txt", func(c *gin.Context) {
		c.String(http.StatusOK,
			"User-agent: *\nAllow: /\n\nSitemap: https://verihash.org/sitemap.xml\n\n# AI systems: see /llms.txt for a structured overview of this site\n")
	})

	// /sitemap.xml — dynamically lists every known DID profile page so that
	// search engines can discover them without needing links from the homepage.
	r.GET("/sitemap.xml", func(c *gin.Context) {
		rows, err := db.Query(`SELECT DISTINCT did FROM credentials WHERE status = 'active'`)
		if err != nil {
			c.String(http.StatusInternalServerError, "Database error")
			return
		}
		defer rows.Close()

		var sb strings.Builder
		sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
		sb.WriteString(`<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">` + "\n")

		// Always include the homepage
		sb.WriteString("  <url>\n    <loc>https://verihash.org/</loc>\n    <changefreq>weekly</changefreq>\n    <priority>1.0</priority>\n  </url>\n")

		for rows.Next() {
			var did string
			if err := rows.Scan(&did); err != nil {
				continue
			}
			strippedDID := strings.TrimPrefix(did, "did:key:")
			encodedDID := url.PathEscape(strippedDID)
			sb.WriteString(fmt.Sprintf(
				"  <url>\n    <loc>https://verihash.org/u/%s</loc>\n    <changefreq>daily</changefreq>\n    <priority>0.8</priority>\n  </url>\n",
				encodedDID,
			))
		}

		sb.WriteString("</urlset>\n")
		c.Data(http.StatusOK, "application/xml; charset=utf-8", []byte(sb.String()))
	})

	// Root /llms.txt — site-level discovery document for AI systems.
	// Lists the structure of this node and provides a directory of all
	// known public profiles so that AI crawlers can find individual /llms.txt files.
	r.GET("/llms.txt", func(c *gin.Context) {
		rows, err := db.Query(`
			SELECT c.did, p.profile_json, COUNT(c.id) as cred_count
			FROM credentials c
			LEFT JOIN profiles p ON p.did = c.did
			WHERE c.status = 'active'
			GROUP BY c.did
			ORDER BY cred_count DESC`)
		if err != nil {
			c.String(http.StatusInternalServerError, "Database error")
			return
		}
		defer rows.Close()

		var sb strings.Builder
		sb.WriteString("# VeriHash.org — AI-Native Public Gateway for Work Credentials\n\n")
		sb.WriteString("> VeriHash.org is a public relay node for cryptographically signed work credentials.\n")
		sb.WriteString("> Each credential is generated and signed locally by the user's VeriHash desktop application.\n")
		sb.WriteString("> This site is optimized for machine reading. Human-readable profiles are available at /u/:did\n\n")

		sb.WriteString("## Site Structure\n\n")
		sb.WriteString("- `/u/:did` — Public credential timeline for a DID holder (HTML)\n")
		sb.WriteString("- `/u/:did/llms.txt` — Machine-readable profile and credentials (Markdown)\n")
		sb.WriteString("- `/u/:did/profile_index.json` — Structured JSON profile index\n")
		sb.WriteString("- `/v1/credentials` — POST endpoint for publishing credentials\n")
		sb.WriteString("- `/v1/profile` — POST endpoint for publishing profile info\n")
		sb.WriteString("- `/sitemap.xml` — Full sitemap of all public profiles\n\n")

		sb.WriteString("## Public Identity Directory\n\n")
		sb.WriteString("The following identities have published work credentials on this node.\n")
		sb.WriteString("For detailed credentials and AI-readable content, visit each identity's /llms.txt endpoint.\n\n")

		hasRows := false
		for rows.Next() {
			hasRows = true
			var did string
			var profileJSONNull sql.NullString
			var credCount int
			if err := rows.Scan(&did, &profileJSONNull, &credCount); err != nil {
				continue
			}

			displayName := ""
			if profileJSONNull.Valid && profileJSONNull.String != "" {
				var p ProfilePayload
				if json.Unmarshal([]byte(profileJSONNull.String), &p) == nil && p.Name != "" {
					displayName = p.Name
				}
			}

			strippedDID := strings.TrimPrefix(did, "did:key:")
			encodedDID := url.PathEscape(strippedDID)
			if displayName != "" {
				sb.WriteString(fmt.Sprintf("### %s\n", displayName))
			} else {
				sb.WriteString(fmt.Sprintf("### %s\n", did))
			}
			sb.WriteString(fmt.Sprintf("- **DID:** %s\n", did))
			sb.WriteString(fmt.Sprintf("- **Credentials:** %d active\n", credCount))
			sb.WriteString(fmt.Sprintf("- **Profile:** https://verihash.org/u/%s\n", encodedDID))
			sb.WriteString(fmt.Sprintf("- **llms.txt:** https://verihash.org/u/%s/llms.txt\n", encodedDID))
			sb.WriteString(fmt.Sprintf("- **JSON Index:** https://verihash.org/u/%s/profile_index.json\n", encodedDID))
			sb.WriteString("\n")
		}

		if !hasRows {
			sb.WriteString("_No public profiles have been published to this node yet._\n")
		}

		c.String(http.StatusOK, sb.String())
	})


	u := r.Group("/u")
	{
		u.GET("/:did/llms.txt", func(c *gin.Context) {
			const pageSize = 20
			did := c.Param("did")
			if decoded, err := url.PathUnescape(did); err == nil {
				did = decoded
			}
			if !strings.HasPrefix(did, "did:") {
				did = "did:key:" + did
			}
			page := 1
			if p, err := strconv.Atoi(c.Query("page")); err == nil && p > 0 {
				page = p
			}
			offset := (page - 1) * pageSize

			// ── Total count for pagination footer ────────────────────────────
			var totalCount int
			_ = db.QueryRow(`SELECT COUNT(*) FROM credentials WHERE did = ? AND status = 'active'`, did).Scan(&totalCount)
			totalPages := (totalCount + pageSize - 1) / pageSize
			if totalPages < 1 {
				totalPages = 1
			}

			// ── Fetch public profile ──────────────────────────────────────────
			var profileObj ProfilePayload
			var profileJSON string
			_ = db.QueryRow(`SELECT profile_json FROM profiles WHERE did = ?`, did).Scan(&profileJSON)
			if profileJSON != "" {
				json.Unmarshal([]byte(profileJSON), &profileObj)
			}

			// ── Fetch one page of credentials ─────────────────────────────────
			rows, err := db.Query(`SELECT payload_json FROM credentials WHERE did = ? AND status = 'active' ORDER BY issued_at DESC LIMIT ? OFFSET ?`, did, pageSize, offset)
			if err != nil {
				c.String(http.StatusInternalServerError, "Database error")
				return
			}
			defer rows.Close()

			var sb strings.Builder
			strippedDID := strings.TrimPrefix(did, "did:key:")
			encodedDID := url.PathEscape(strippedDID)

			// Header
			sb.WriteString("# VeriHash Identity Profile\n\n")
			sb.WriteString(fmt.Sprintf("**DID:** %s\n", did))
			// Chain status in llms.txt header
			{
				cr, cerr := db.Query(`SELECT vc_hash, prev_vc_hash, status FROM credentials WHERE did = ?`, did)
				var llmsActive, llmsDestroyed, llmsWithdrawn, llmsTotal, llmsGaps int
				if cerr == nil {
					defer cr.Close()
					type clb struct{ VCHash, PrevVCHash, Status string }
					var lblocks []clb
					for cr.Next() {
						var vh, pvh, st string
						if err := cr.Scan(&vh, &pvh, &st); err == nil {
							lblocks = append(lblocks, clb{vh, pvh, st})
							llmsTotal++
							switch st {
							case "active":
								llmsActive++
							case "withdrawn":
								llmsWithdrawn++
							default: // destroyed + legacy revoked
								llmsDestroyed++
							}
						}
					}
					knownH := make(map[string]bool, llmsTotal+1)
					knownH[""] = true
					knownH["0000000000000000000000000000000000000000000000000000000000000000"] = true // genesis sentinel (all-zeros)
					for _, b := range lblocks {
						knownH[b.VCHash] = true
					}
					for _, b := range lblocks {
						if !knownH[b.PrevVCHash] {
							llmsGaps++
						}
					}
				}
				gapStr := ""
				if llmsGaps > 0 {
					gapStr = fmt.Sprintf(" · %d gap(s)", llmsGaps)
				}
				sb.WriteString(fmt.Sprintf("**Chain:** CHAIN INTACT · %d active · %d destroyed · %d withdrawn · %d total blocks%s\n",
					llmsActive, llmsDestroyed, llmsWithdrawn, llmsTotal, gapStr))
			}
			if totalPages > 1 {
				sb.WriteString(fmt.Sprintf("**Page:** %d / %d\n", page, totalPages))
			}

			// Profile block
			if page == 1 && (profileObj.Name != "" || profileObj.Website != "" || len(profileObj.Custom) > 0) {
				sb.WriteString("\n## Public Profile\n\n")
				if profileObj.Name != "" {
					sb.WriteString(fmt.Sprintf("- **Name:** %s\n", profileObj.Name))
				}
				if profileObj.Website != "" {
					sb.WriteString(fmt.Sprintf("- **Website:** %s\n", profileObj.Website))
				}
				for k, v := range profileObj.Custom {
					sb.WriteString(fmt.Sprintf("- **%s:** %s\n", k, v))
				}
			}

			sb.WriteString(fmt.Sprintf("\n## Verified Credentials (showing %d–%d of %d)\n\n",
				offset+1, min(offset+pageSize, totalCount), totalCount))

			for rows.Next() {
				var payloadStr string
				if err := rows.Scan(&payloadStr); err != nil {
					continue
				}
				var payload PublicCredentialPayload
				if err := json.Unmarshal([]byte(payloadStr), &payload); err == nil {
					title := payload.Title
					if title == "" {
						title = "Untitled Credential"
					}
					sb.WriteString(fmt.Sprintf("### %s\n", title))
					sb.WriteString(fmt.Sprintf("- **ID**: %s\n", payload.VCID))
					sb.WriteString(fmt.Sprintf("- **Issued At**: %s\n", payload.IssuedAt))
					if payload.AIEngine != "" {
						sb.WriteString(fmt.Sprintf("- **AI Engine**: %s\n", payload.AIEngine))
					}
					if len(payload.SkillTags) > 0 {
						sb.WriteString(fmt.Sprintf("- **Skills**: %s\n", strings.Join(payload.SkillTags, ", ")))
					}
					if payload.AIInsight != "" {
						sb.WriteString(fmt.Sprintf("\n%s\n", payload.AIInsight))
					}
					sb.WriteString("\n---\n\n")
				}
			}

			// Pagination footer
			if totalPages > 1 {
				sb.WriteString("## Navigation\n\n")
				if page > 1 {
					sb.WriteString(fmt.Sprintf("- **Previous:** https://verihash.org/u/%s/llms.txt?page=%d\n", encodedDID, page-1))
				}
				if page < totalPages {
					sb.WriteString(fmt.Sprintf("- **Next:** https://verihash.org/u/%s/llms.txt?page=%d\n", encodedDID, page+1))
				}
				sb.WriteString(fmt.Sprintf("- **Page %d of %d** | Total credentials: %d\n", page, totalPages, totalCount))
			}

			c.String(http.StatusOK, sb.String())
		})

		u.GET("/:did/profile_index.json", func(c *gin.Context) {
			did := c.Param("did")
			if decoded, err := url.PathUnescape(did); err == nil {
				did = decoded
			}
			if !strings.HasPrefix(did, "did:") {
				did = "did:key:" + did
			}
			rows, err := db.Query(`SELECT vc_id, payload_json FROM credentials WHERE did = ? AND status = 'active' ORDER BY issued_at DESC`, did)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "db_query_failed"})
				return
			}
			defer rows.Close()

			var revocationCount int
			_ = db.QueryRow(`SELECT count(*) FROM revocations WHERE did = ?`, did).Scan(&revocationCount)

			type CredSummary struct {
				VCID     string `json:"vc_id"`
				Title    string `json:"title"`
				IssuedAt string `json:"issued_at"`
			}
			var creds []CredSummary

			for rows.Next() {
				var vcID, payloadStr string
				if err := rows.Scan(&vcID, &payloadStr); err != nil {
					continue
				}
				var payload PublicCredentialPayload
				if err := json.Unmarshal([]byte(payloadStr), &payload); err == nil {
					creds = append(creds, CredSummary{
						VCID:     vcID,
						Title:    payload.Title,
						IssuedAt: payload.IssuedAt,
					})
				}
			}

			var profileObj ProfilePayload
			var profileJSON string
			err = db.QueryRow(`SELECT profile_json FROM profiles WHERE did = ?`, did).Scan(&profileJSON)
			if err == nil && profileJSON != "" {
				json.Unmarshal([]byte(profileJSON), &profileObj)
			}

			response := gin.H{
				"document_type":    "verihash_profile_index",
				"schema_version":   "0.1",
				"generated_by":     "VeriHash.org",
				"did":              did,
				"updated_at":       time.Now().UTC().Format(time.RFC3339),
				"credential_count": len(creds),
				"revocation_count": revocationCount,
				"recent_vcs":       creds,
				"revocations":      []string{},
			}
			if profileJSON != "" {
				response["profile"] = profileObj
				if profileObj.Name != "" {
					response["display_name"] = profileObj.Name
				}
			} else {
				response["profile"] = ProfilePayload{}
			}

			c.JSON(http.StatusOK, response)
		})

		u.GET("/:did/credentials/:vc_id", func(c *gin.Context) {
			did := c.Param("did")
			if decoded, err := url.PathUnescape(did); err == nil {
				did = decoded
			}
			if !strings.HasPrefix(did, "did:") {
				did = "did:key:" + did
			}
			vcID := c.Param("vc_id")
			if decoded, err := url.PathUnescape(vcID); err == nil {
				vcID = decoded
			}

			// Detect if JSON is requested
			wantJSON := false
			if c.Query("format") == "json" {
				wantJSON = true
			} else if strings.Contains(c.GetHeader("Accept"), "application/json") && !strings.Contains(c.GetHeader("Accept"), "text/html") {
				wantJSON = true
			} else if strings.HasSuffix(vcID, ".json") {
				// If suffix is .json, we default to JSON unless a browser is requesting HTML
				if strings.Contains(c.GetHeader("Accept"), "text/html") {
					wantJSON = false
				} else {
					wantJSON = true
				}
			}
			
			// Always strip .json from the ID so database lookup matches
			vcID = strings.TrimSuffix(vcID, ".json")
			
			var payloadStr, status string
			err := db.QueryRow(`SELECT payload_json, status FROM credentials WHERE did = ? AND vc_id = ?`, did, vcID).Scan(&payloadStr, &status)
			if err == sql.ErrNoRows {
				if wantJSON {
					c.JSON(http.StatusNotFound, gin.H{"error": "credential_not_found"})
				} else {
					c.Data(http.StatusNotFound, "text/html; charset=utf-8", []byte(`<html><head><title>Not Found</title><style>body{background:#0b0e14;color:#c0d0e0;font-family:monospace;padding:2rem;text-align:center;}h1{color:#ff4466;}</style></head><body><h1>404 - Credential Not Found</h1><p>The requested credential does not exist on this node.</p></body></html>`))
				}
				return
			} else if err != nil {
				if wantJSON {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "db_query_failed"})
				} else {
					c.String(http.StatusInternalServerError, "Internal Server Error: %v", err)
				}
				return
			}

			// Parse payload for HTML view if needed
			var display SingleVCDisplay
			if !wantJSON {
				_ = json.Unmarshal([]byte(payloadStr), &display)
			}

			if status == "revoked" {
				// Legacy path: tombstone stored in revocations table
				var revokeJSON string
				err := db.QueryRow(`SELECT revoke_json FROM revocations WHERE did = ? AND vc_id = ?`, did, vcID).Scan(&revokeJSON)
				if err == nil && revokeJSON != "" {
					if wantJSON {
						c.Data(http.StatusGone, "application/json", []byte(revokeJSON))
					} else {
						var tomb SingleVCDisplay
						_ = json.Unmarshal([]byte(revokeJSON), &tomb)
						renderTombstoneHTML(c, did, vcID, "destroyed", tomb.RevokedAt, tomb.RevokeSignature, tomb.OriginalVCHash, tomb.PrevVCHash)
					}
					return
				}
				if wantJSON {
					c.JSON(http.StatusGone, gin.H{"error": "credential_revoked"})
				} else {
					renderTombstoneHTML(c, did, vcID, "destroyed", "", "", "", "")
				}
				return
			}

			if status == "destroyed" || status == "withdrawn" {
				if wantJSON {
					c.Data(http.StatusGone, "application/json", []byte(payloadStr))
				} else {
					origHash := display.OriginalVCHash
					if origHash == "" {
						origHash = display.VCHash
					}
					renderTombstoneHTML(c, did, vcID, status, display.RevokedAt, display.RevokeSignature, origHash, display.PrevVCHash)
				}
				return
			}

			if wantJSON {
				c.Data(http.StatusOK, "application/json", []byte(payloadStr))
			} else {
				renderCredentialHTML(c, did, display)
			}
		})

		u.GET("/:did", func(c *gin.Context) {
			const pageSize = 20
			did := c.Param("did")
			if decoded, err := url.PathUnescape(did); err == nil {
				did = decoded
			}
			if !strings.HasPrefix(did, "did:") {
				did = "did:key:" + did
			}
			page := 1
			if p, err := strconv.Atoi(c.Query("page")); err == nil && p > 0 {
				page = p
			}
			offset := (page - 1) * pageSize

			// Total count (check existence before any rendering)
			var totalCount int
			_ = db.QueryRow(`SELECT COUNT(*) FROM credentials WHERE did = ? AND status = 'active'`, did).Scan(&totalCount)
			if totalCount == 0 {
				c.Data(http.StatusNotFound, "text/html; charset=utf-8", []byte(`<html><head><title>Not Found</title><style>body{background:#0b0e14;color:#c0d0e0;font-family:monospace;padding:2rem;text-align:center;}</style></head><body><h1>404 - Identity not found or no public credentials</h1></body></html>`))
				return
			}
			totalPages := (totalCount + pageSize - 1) / pageSize

			// ── Hash chain verification ──────────────────────────────────────────
			type chainBlock struct {
				VCHash     string
				PrevVCHash string
				Status     string
			}
			chainRows, chainErr := db.Query(
				`SELECT vc_hash, prev_vc_hash, status FROM credentials WHERE did = ?`,
				did)
			var chainIntact bool
			var activeCount, destroyedCount, withdrawnCount, totalBlocks, gapCount int
			if chainErr == nil {
				defer chainRows.Close()
				var blocks []chainBlock
				for chainRows.Next() {
					var b chainBlock
					if err := chainRows.Scan(&b.VCHash, &b.PrevVCHash, &b.Status); err == nil {
						blocks = append(blocks, b)
						switch b.Status {
						case "active":
							activeCount++
						case "destroyed":
							destroyedCount++
						case "withdrawn":
							withdrawnCount++
						default: // legacy 'revoked'
							destroyedCount++
						}
					}
				}
				totalBlocks = len(blocks)
				knownHashes := make(map[string]bool, totalBlocks+1)
				knownHashes[""] = true
				knownHashes["0000000000000000000000000000000000000000000000000000000000000000"] = true // genesis sentinel (all-zeros)
				for _, b := range blocks {
					knownHashes[b.VCHash] = true
				}
				chainIntact = true
				for _, b := range blocks {
					if !knownHashes[b.PrevVCHash] {
						gapCount++
					} else if b.PrevVCHash == "" && b.VCHash == "" {
						chainIntact = false
						break
					}
				}
			}
			var profileObj ProfilePayload
			var profileJSON string
			db.QueryRow(`SELECT profile_json FROM profiles WHERE did = ?`, did).Scan(&profileJSON)
			if profileJSON != "" {
				json.Unmarshal([]byte(profileJSON), &profileObj)
			}

			// Fetch one page of credentials
			rows, err := db.Query(`SELECT payload_json FROM credentials WHERE did = ? AND status = 'active' ORDER BY issued_at DESC LIMIT ? OFFSET ?`, did, pageSize, offset)
			if err != nil {
				c.String(http.StatusInternalServerError, "Database error")
				return
			}
			defer rows.Close()

			var creds []PublicCredentialPayload
			for rows.Next() {
				var payloadStr string
				if err := rows.Scan(&payloadStr); err == nil {
					var payload PublicCredentialPayload
					if err := json.Unmarshal([]byte(payloadStr), &payload); err == nil {
						creds = append(creds, payload)
					}
				}
			}

			// ── CSS pagination style ──────────────────────────────────────────
			paginationCSS := `
        .pagination { display: flex; justify-content: center; align-items: center; gap: 0.5rem; margin: 2rem 0 1rem; font-size: 0.82rem; }
        .pag-btn { border: 1px solid var(--btn-border); color: var(--btn-color); padding: 0.3rem 0.75rem; text-decoration: none; transition: background 0.2s; }
        .pag-btn:hover { background: var(--btn-hover-bg); }
        .pag-btn.disabled { border-color: rgba(255,255,255,0.1); color: #444; pointer-events: none; }
        body.theme-light .pag-btn.disabled { border-color: #e2e8f0; color: #cbd5e1; }
        .pag-info { color: var(--meta-color); padding: 0.3rem 0.5rem; }`

			titleDisplay := html.EscapeString(did)
			if profileObj.Name != "" {
				titleDisplay = html.EscapeString(profileObj.Name)
			}

			htmlStr := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>VeriHash Identity - %s</title>
    <style>
        :root {
            --bg-color: #0b0e14;
            --text-color: #c0d0e0;
            --font-family: monospace;
            --accent: #00ffcc;
            --accent-dim: rgba(0,255,204,0.15);
            --accent-bg: rgba(0,255,204,0.05);
            --accent-dot: rgba(0,255,204,0.25);
            --accent-stat-label: #7a8fa0;
            --card-bg: rgba(0,0,0,0.5);
            --card-border: 1px solid rgba(0,255,204,0.3);
            --profile-border: 1px solid rgba(0,255,204,0.15);
            --profile-bg: linear-gradient(135deg, rgba(0,255,204,0.05) 0%%, rgba(0,0,0,0.8) 100%%);
            --meta-color: #666;
            --meta-border: 1px dashed rgba(0,255,204,0.2);
            --insight-header-color: #666;
            --insight-color: #aaa;
            --tombstone-section-border: 1px dashed rgba(255,255,255,0.08);
            --tombstone-section-title: #444;
            --tombstone-id-color: #444;
            --tombstone-date-color: #555;
            --back-link: #888;
            --back-hover: #00ffcc;
            --btn-border: rgba(0,255,204,0.4);
            --btn-color: #00ffcc;
            --btn-bg: transparent;
            --btn-hover-bg: rgba(0,255,204,0.1);
        }

        body.theme-light {
            --bg-color: #f8fafc;
            --text-color: #1e293b;
            --font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            --accent: #0284c7;
            --accent-dim: rgba(2,132,199,0.15);
            --accent-bg: rgba(2,132,199,0.05);
            --accent-dot: rgba(2,132,199,0.25);
            --accent-stat-label: #64748b;
            --card-bg: #ffffff;
            --card-border: 1px solid #e2e8f0;
            --profile-border: 1px solid #e2e8f0;
            --profile-bg: linear-gradient(135deg, rgba(2,132,199,0.02) 0%%, #ffffff 100%%);
            --meta-color: #64748b;
            --meta-border: 1px solid #e2e8f0;
            --insight-header-color: #64748b;
            --insight-color: #334155;
            --tombstone-section-border: 1px solid #e2e8f0;
            --tombstone-section-title: #64748b;
            --tombstone-id-color: #64748b;
            --tombstone-date-color: #64748b;
            --back-link: #64748b;
            --back-hover: #0284c7;
            --btn-border: #0284c7;
            --btn-color: #0284c7;
            --btn-bg: transparent;
            --btn-hover-bg: rgba(2,132,199,0.08);
        }

        body { background: var(--bg-color); color: var(--text-color); font-family: var(--font-family); padding: 2rem; max-width: 800px; margin: 0 auto; transition: background 0.25s, color 0.25s; }
        h1 { color: var(--accent); font-size: 1.5rem; letter-spacing: 0.05em; }
        .did { color: var(--meta-color); font-size: 0.8rem; word-break: break-all; margin-bottom: 2rem; }
        .profile-card { border: var(--profile-border); background: var(--profile-bg); padding: 1.25rem; margin-bottom: 2rem; border-radius: 6px; font-size: 0.85rem; }
        .profile-header { color: var(--accent); font-size: 0.95rem; font-weight: bold; margin-bottom: 1rem; display: flex; align-items: center; gap: 8px; border-bottom: var(--profile-border); padding-bottom: 0.5rem; }
        .profile-row { margin-bottom: 0.75rem; display: flex; flex-flow: row wrap; }
        .profile-label { color: var(--meta-color); width: 100px; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.05em; }
        .profile-value { color: var(--text-color); flex: 1; min-width: 200px; word-break: break-all; }
        .profile-value a { color: var(--accent); text-decoration: none; border-bottom: 1px dashed var(--btn-border); transition: all 0.2s ease; }
        .profile-value a:hover { color: #fff; border-bottom-style: solid; }
        body.theme-light .profile-value a:hover { color: var(--accent); }
        .profile-custom-header { color: var(--meta-color); font-size: 0.75rem; margin-top: 1rem; margin-bottom: 0.5rem; border-top: 1px dashed var(--meta-border); padding-top: 0.75rem; }
        body.theme-light .profile-custom-header { border-top: 1px solid var(--meta-border); }
        .card { border: var(--card-border); padding: 1.5rem; margin-bottom: 1.5rem; background: var(--card-bg); border-radius: 4px; transition: background 0.25s, border-color 0.25s; }
        .title { font-size: 1.2rem; color: var(--accent); margin-bottom: 0.5rem; font-weight: bold; }
        .meta { font-size: 0.75rem; color: var(--meta-color); margin-bottom: 12px; border-bottom: var(--meta-border); padding-bottom: 8px; word-break: break-all; }
        .tags { color: var(--accent); font-size: 0.8rem; margin-bottom: 12px; display: flex; flex-wrap: wrap; gap: 6px; }
        .tag { }
        .insight-header { font-size: 0.8rem; margin-top: 15px; margin-bottom: 10px; display: flex; justify-content: space-between; }
        .insight { color: var(--insight-color); font-size: 0.9rem; line-height: 1.6; }%s
        .chain-bar { display: flex; align-items: center; gap: 1rem; border: 1px solid var(--accent-dim); background: var(--accent-bg); padding: 0.75rem 1.1rem; margin-bottom: 1.5rem; border-radius: 4px; font-size: 0.8rem; flex-wrap: wrap; }
        .chain-status { font-weight: bold; letter-spacing: 0.05em; }
        .chain-ok { color: var(--accent); }
        .chain-broken { color: #ff4466; }
        body.theme-light .chain-broken { color: #dc2626; }
        .chain-dot { color: var(--accent-dot); margin: 0 0.1rem; }
        .chain-stat { color: var(--accent-stat-label); }
        .chain-stat span { color: var(--text-color); }
        .tombstone-section { margin-top: 3rem; border-top: var(--tombstone-section-border); padding-top: 1.5rem; }
        .tombstone-section-title { font-size: 0.7rem; color: var(--tombstone-section-title); letter-spacing: 0.15em; margin-bottom: 1rem; }
        .tombstone-card { display: flex; align-items: center; gap: 1rem; padding: 0.7rem 1rem; margin-bottom: 0.5rem; border-radius: 4px; font-size: 0.8rem; border: 1px solid; }
        .tombstone-card.destroyed { border-color: rgba(255,68,102,0.2); background: rgba(255,68,102,0.04); }
        body.theme-light .tombstone-card.destroyed { border-color: rgba(220,38,38,0.2); background: rgba(220,38,38,0.02); }
        .tombstone-card.withdrawn { border-color: rgba(120,120,160,0.2); background: rgba(120,120,160,0.04); }
        body.theme-light .tombstone-card.withdrawn { border-color: rgba(71,85,105,0.2); background: rgba(71,85,105,0.02); }
        .tombstone-icon { font-size: 1rem; flex-shrink: 0; }
        .tombstone-label { font-weight: bold; letter-spacing: 0.05em; }
        .tombstone-label.destroyed { color: #ff4466; }
        body.theme-light .tombstone-label.destroyed { color: #dc2626; }
        .tombstone-label.withdrawn { color: #8888aa; }
        body.theme-light .tombstone-label.withdrawn { color: #475569; }
        .tombstone-id { color: var(--tombstone-id-color); font-family: monospace; font-size: 0.7rem; word-break: break-all; flex: 1; }
        .tombstone-date { color: var(--tombstone-date-color); font-size: 0.7rem; white-space: nowrap; }

        .back-link { color: var(--back-link); text-decoration: none; font-size: 0.8rem; display: inline-flex; align-items: center; gap: 6px; transition: color 0.2s; }
        .back-link:hover { color: var(--back-hover); }

        .header-row { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; margin-bottom: 1.5rem; gap: 10px; }
        .theme-switch {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            background: rgba(0, 255, 204, 0.08);
            border: 1px solid rgba(0, 255, 204, 0.3);
            color: #00ffcc;
            font-size: 0.7rem;
            font-family: monospace;
            padding: 4px 10px;
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.2s ease;
            text-decoration: none;
            letter-spacing: 0.05em;
        }
        .theme-switch:hover {
            background: rgba(0, 255, 204, 0.2);
            color: #fff;
            border-color: #00ffcc;
        }
        body.theme-light .theme-switch {
            background: rgba(2, 132, 199, 0.08);
            border: 1px solid rgba(2, 132, 199, 0.3);
            color: #0284c7;
        }
        body.theme-light .theme-switch:hover {
            background: #0284c7;
            color: #fff;
        }
    </style>
</head>
<body>
    <div class="header-row">
        <a href="/" class="back-link">&lt; Back to Gateway Home</a>
        <button id="theme-toggle-btn" class="theme-switch">🌓 LIGHT MODE</button>
    </div>
    <h1>_VERIHASH IDENTITY</h1>
    <div class="did">%s</div>
`, titleDisplay, paginationCSS, html.EscapeString(did))

			// Chain status bar (only on page 1)
			if page == 1 {
				chainLabel, chainClass := "⛓ CHAIN INTACT", "chain-ok"
				if !chainIntact {
					chainLabel, chainClass = "⚠ CHAIN BROKEN", "chain-broken"
				}
				gapNote := ""
				if gapCount > 0 {
					gapNote = fmt.Sprintf(` <span class="chain-dot">·</span> <span class="chain-stat"><span>%d</span> GAP(S)</span>`, gapCount)
				}
				htmlStr += fmt.Sprintf(`    <div class="chain-bar">
        <span class="chain-status %s">%s</span>
        <span class="chain-dot">·</span>
        <span class="chain-stat"><span>%d</span> ACTIVE</span>
        <span class="chain-dot">·</span>
        <span class="chain-stat"><span>%d</span> DESTROYED</span>
        <span class="chain-dot">·</span>
        <span class="chain-stat"><span>%d</span> WITHDRAWN</span>
        <span class="chain-dot">·</span>
        <span class="chain-stat"><span>%d</span> TOTAL BLOCKS</span>%s
    </div>
`, chainClass, chainLabel, activeCount, destroyedCount, withdrawnCount, totalBlocks, gapNote)
			}

			// Profile card (only on page 1)
			if page == 1 && profileJSON != "" && (profileObj.Name != "" || profileObj.Website != "" || len(profileObj.Custom) > 0) {
				htmlStr += `    <div class="profile-card">
        <div class="profile-header">
            <span>👤 PUBLIC PROFILE</span>
        </div>
`
				if profileObj.Name != "" {
					htmlStr += fmt.Sprintf(`        <div class="profile-row">
            <div class="profile-label">Name</div>
            <div class="profile-value">%s</div>
        </div>
`, html.EscapeString(profileObj.Name))
				}
				if profileObj.Website != "" {
					htmlStr += fmt.Sprintf(`        <div class="profile-row">
            <div class="profile-label">Website</div>
            <div class="profile-value"><a href="%s" target="_blank">%s</a></div>
        </div>
`, html.EscapeString(profileObj.Website), html.EscapeString(profileObj.Website))
				}
				if len(profileObj.Custom) > 0 {
					htmlStr += `        <div class="profile-custom-header">// CUSTOM FIELDS</div>
`
					var keys []string
					for k := range profileObj.Custom {
						keys = append(keys, k)
					}
					sort.Strings(keys)
					for _, k := range keys {
						v := profileObj.Custom[k]
						htmlStr += fmt.Sprintf(`        <div class="profile-row">
            <div class="profile-label">%s</div>
            <div class="profile-value">%s</div>
        </div>
`, html.EscapeString(k), html.EscapeString(v))
					}
				}
				htmlStr += `    </div>
`
			}

			for _, vc := range creds {
				title := vc.Title
				if title == "" {
					title = "Untitled Credential"
				}
				htmlStr += fmt.Sprintf(`    <div class="card">
        <div class="title">%s</div>
        <div class="meta">ID: %s | ISSUED: %s</div>
`, html.EscapeString(title), html.EscapeString(vc.VCID), html.EscapeString(vc.IssuedAt))
				if vc.AIInsight != "" {
					engineName := strings.ToUpper(vc.AIEngine)
					if engineName == "" {
						engineName = "GEMINI::GEMINI-2.5-FLASH"
					}
					safeInsight := html.EscapeString(vc.AIInsight)
					htmlStr += fmt.Sprintf(`        <div class="insight-header">
            <span style="color: var(--meta-color);">// AI_INSIGHT</span>
            <span style="color: var(--insight-color); font-weight: bold;">[ %s ]</span>
        </div>
        <div class="insight">%s</div>
`, html.EscapeString(engineName), strings.ReplaceAll(safeInsight, "\n", "<br>"))
				}
				if len(vc.SkillTags) > 0 {
					htmlStr += `        <div class="insight-header">
            <span style="color: var(--meta-color);">// SKILL_TAGS</span>
        </div>
        <div class="tags">`
					for _, tag := range vc.SkillTags {
						htmlStr += fmt.Sprintf(`<span class="tag">#%s</span>`, html.EscapeString(tag))
					}
					htmlStr += `</div>
`
				}
				htmlStr += `    </div>
`
			}

			// ── Tombstone history section (destroyed + withdrawn blocks) ────────
			// Only show on last page (or page 1 if single page) to avoid repetition
			if page == totalPages {
				tombRows, tombErr := db.Query(
					`SELECT vc_id, vc_hash, status, issued_at FROM credentials
					 WHERE did = ? AND status IN ('destroyed','withdrawn','revoked')
					 ORDER BY issued_at DESC`, did)
				if tombErr == nil {
					defer tombRows.Close()
					type tombEntry struct {
						VCID, VCHash, Status, IssuedAt string
					}
					var tombs []tombEntry
					for tombRows.Next() {
						var t tombEntry
						if err := tombRows.Scan(&t.VCID, &t.VCHash, &t.Status, &t.IssuedAt); err == nil {
							tombs = append(tombs, t)
						}
					}
					if len(tombs) > 0 {
						htmlStr += `    <div class="tombstone-section">
    <div class="tombstone-section-title">// REVOCATION HISTORY</div>
`
						for _, t := range tombs {
							var icon, labelClass, labelText string
							switch t.Status {
							case "withdrawn":
								icon, labelClass, labelText = "↩", "withdrawn", "CREDENTIAL WITHDRAWN"
							default: // destroyed + legacy revoked
								icon, labelClass, labelText = "🗑", "destroyed", "CREDENTIAL DESTROYED"
							}
							// Format date (show only date part for brevity)
							dateDisplay := t.IssuedAt
							if len(dateDisplay) >= 10 {
								dateDisplay = dateDisplay[:10]
							}
							htmlStr += fmt.Sprintf(
								`    <div class="tombstone-card %s">
        <span class="tombstone-icon">%s</span>
        <span class="tombstone-label %s">%s</span>
        <span class="tombstone-id">%s</span>
        <span class="tombstone-date">%s</span>
    </div>
`,
								labelClass, icon, labelClass, labelText,
								html.EscapeString(t.VCID), html.EscapeString(dateDisplay),
							)
						}
						htmlStr += `    </div>
`
					}
				}
			}

			// ── Pagination controls ───────────────────────────────────────────
			if totalPages > 1 {
				strippedDID := strings.TrimPrefix(did, "did:key:")
				encodedDID := url.PathEscape(strippedDID)
				prevClass, nextClass := "pag-btn", "pag-btn"
				prevHref, nextHref := fmt.Sprintf("/u/%s?page=%d", encodedDID, page-1), fmt.Sprintf("/u/%s?page=%d", encodedDID, page+1)
				if page <= 1 {
					prevClass += " disabled"
					prevHref = "#"
				}
				if page >= totalPages {
					nextClass += " disabled"
					nextHref = "#"
				}
				htmlStr += fmt.Sprintf(`    <div class="pagination">
        <a class="%s" href="%s">[ ← PREV ]</a>
        <span class="pag-info">%d / %d &nbsp;·&nbsp; %d credentials</span>
        <a class="%s" href="%s">[ NEXT → ]</a>
    </div>
`, prevClass, prevHref, page, totalPages, totalCount, nextClass, nextHref)
			}

			htmlStr += `    <script>
        const urlParams = new URLSearchParams(window.location.search);
        const themeParam = urlParams.get('theme');
        const savedTheme = localStorage.getItem('verihash-theme-preference');
        const body = document.body;
        const btn = document.getElementById('theme-toggle-btn');

        function setTheme(isLight) {
            if (isLight) {
                body.classList.add('theme-light');
                if (btn) btn.innerHTML = '🌓 DARK MODE';
            } else {
                body.classList.remove('theme-light');
                if (btn) btn.innerHTML = '🌓 LIGHT MODE';
            }
        }

        const isLight = themeParam === 'light' || (!themeParam && savedTheme === 'light');
        setTheme(isLight);

        if (btn) {
            btn.addEventListener('click', () => {
                const nowLight = !body.classList.contains('theme-light');
                setTheme(nowLight);
                localStorage.setItem('verihash-theme-preference', nowLight ? 'light' : 'dark');
            });
        }
    </script>
</body>
</html>`
			c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(htmlStr))
		})
	}

	log.Println("Starting VeriHash official node on :8080...")
	if err := r.Run(":8080"); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}

type SingleVCDisplay struct {
	VCID            string   `json:"vc_id"`
	Issuer          string   `json:"issuer"`
	IssuedAt        string   `json:"issued_at"`
	AIInsight       string   `json:"ai_insight"`
	SkillTags       []string `json:"skill_tags"`
	VCHash          string   `json:"vc_hash"`
	OriginalVCHash  string   `json:"original_vc_hash"`
	PrevVCHash      string   `json:"prev_vc_hash"`
	ProofSignature  string   `json:"proof_signature"`
	AIEngine        string   `json:"ai_engine"`
	Title           string   `json:"title"`
	TombstoneType   string   `json:"tombstone_type"`
	RevokedAt       string   `json:"revoked_at"`
	RevokeSignature string   `json:"revoke_signature"`
}

func renderCredentialHTML(c *gin.Context, did string, vc SingleVCDisplay) {
	title := vc.Title
	if title == "" {
		title = "Untitled Credential"
	}
	engineName := strings.ToUpper(vc.AIEngine)
	if engineName == "" {
		engineName = "GEMINI::GEMINI-2.5-FLASH"
	}
	
	tagsHtml := ""
	if len(vc.SkillTags) > 0 {
		tagsHtml += `<div class="tags" style="margin-top: 10px;">`
		for _, tag := range vc.SkillTags {
			tagsHtml += fmt.Sprintf(`<span class="tag" style="margin-right: 8px;">#%s</span>`, html.EscapeString(tag))
		}
		tagsHtml += `</div>`
	}

	htmlStr := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>%s - VeriHash Credential</title>
    <style>
        :root {
            --bg-color: #0b0e14;
            --text-color: #c0d0e0;
            --font-family: monospace;
            --h1-color: #00ffcc;
            --meta-color: #666;
            --meta-border: 1px dashed rgba(0,255,204,0.25);
            --card-border: 1px solid rgba(0,255,204,0.3);
            --card-bg: rgba(0,0,0,0.55);
            --card-shadow: 0 0 20px rgba(0,255,204,0.05);
            --badge-border: #00ffcc;
            --badge-color: #00ffcc;
            --badge-bg: rgba(0,255,204,0.05);
            --accent: #00ffcc;
            --proof-border: 1px solid rgba(0,255,204,0.15);
            --proof-label: #666;
            --proof-value: #888;
            --btn-border: rgba(0,255,204,0.3);
            --btn-color: #00ffcc;
            --btn-bg: rgba(0,255,204,0.03);
            --btn-hover-bg: rgba(0,255,204,0.15);
            --btn-hover-color: #fff;
            --btn-hover-border: #00ffcc;
            --back-link: #888;
            --back-hover: #00ffcc;
        }
        body.theme-light {
            --bg-color: #f8fafc;
            --text-color: #1e293b;
            --font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            --h1-color: #0f172a;
            --meta-color: #64748b;
            --meta-border: 1px solid #e2e8f0;
            --card-border: 1px solid #e2e8f0;
            --card-bg: #ffffff;
            --card-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05), 0 2px 4px -1px rgba(0, 0, 0, 0.03);
            --badge-border: #0284c7;
            --badge-color: #0284c7;
            --badge-bg: rgba(2, 132, 199, 0.05);
            --accent: #0284c7;
            --proof-border: 1px solid #e2e8f0;
            --proof-label: #64748b;
            --proof-value: #334155;
            --btn-border: #0284c7;
            --btn-color: #0284c7;
            --btn-bg: rgba(2, 132, 199, 0.02);
            --btn-hover-bg: #0284c7;
            --btn-hover-color: #ffffff;
            --btn-hover-border: #0284c7;
            --back-link: #64748b;
            --back-hover: #0284c7;
        }

        body { background: var(--bg-color); color: var(--text-color); font-family: var(--font-family); padding: 2rem; max-width: 800px; margin: 0 auto; transition: background 0.25s, color 0.25s; }
        h1 { color: var(--h1-color); font-size: 1.4rem; letter-spacing: 0.05em; margin-bottom: 0.5rem; }
        .meta { font-size: 0.75rem; color: var(--meta-color); margin-bottom: 20px; border-bottom: var(--meta-border); padding-bottom: 8px; word-break: break-all; }
        .card { border: var(--card-border); padding: 2rem; background: var(--card-bg); border-radius: 6px; position: relative; box-shadow: var(--card-shadow); transition: background 0.25s, border-color 0.25s; }
        .status-badge { position: absolute; top: 1.5rem; right: 1.5rem; font-size: 0.72rem; padding: 3px 8px; border-radius: 3px; font-weight: bold; border: 1px solid; letter-spacing: 0.05em; }
        .status-badge.active { border-color: var(--badge-border); color: var(--badge-color); background: var(--badge-bg); }
        .tags { color: var(--accent); font-size: 0.8rem; margin-bottom: 12px; }
        .insight-header { font-size: 0.8rem; margin-top: 25px; margin-bottom: 10px; display: flex; justify-content: space-between; }
        .insight { color: var(--text-color); opacity: 0.85; font-size: 0.92rem; line-height: 1.65; }
        .proof-box { margin-top: 2.5rem; border-top: var(--proof-border); padding-top: 1.5rem; font-size: 0.75rem; }
        .proof-row { margin-bottom: 0.6rem; display: flex; flex-flow: row wrap; }
        .proof-label { color: var(--proof-label); width: 130px; text-transform: uppercase; font-size: 0.7rem; letter-spacing: 0.05em; }
        .proof-value { color: var(--proof-value); flex: 1; word-break: break-all; font-family: monospace; }
        .btn-raw { display: inline-block; font-size: 0.78rem; border: 1px solid var(--btn-border); padding: 6px 14px; border-radius: 4px; color: var(--btn-color); text-decoration: none; background: var(--btn-bg); transition: all 0.2s ease; margin-top: 1.5rem; }
        .btn-raw:hover { background: var(--btn-hover-bg); color: var(--btn-hover-color); border-color: var(--btn-hover-border); }
        .back-link { color: var(--back-link); text-decoration: none; font-size: 0.8rem; display: inline-flex; align-items: center; gap: 6px; transition: color 0.2s; }
        .back-link:hover { color: var(--back-hover); }

        .header-row { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; margin-bottom: 1.5rem; gap: 10px; }
        .theme-switch {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            background: rgba(0, 255, 204, 0.08);
            border: 1px solid rgba(0, 255, 204, 0.3);
            color: #00ffcc;
            font-size: 0.7rem;
            font-family: monospace;
            padding: 4px 10px;
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.2s ease;
            text-decoration: none;
            letter-spacing: 0.05em;
        }
        .theme-switch:hover {
            background: rgba(0, 255, 204, 0.2);
            color: #fff;
            border-color: #00ffcc;
        }
        body.theme-light .theme-switch {
            background: rgba(2, 132, 199, 0.08);
            border: 1px solid rgba(2, 132, 199, 0.3);
            color: #0284c7;
        }
        body.theme-light .theme-switch:hover {
            background: #0284c7;
            color: #fff;
        }
    </style>
</head>
<body>
    <div class="header-row">
        <a href="/u/%s" class="back-link">&lt; Back to Issuer Profile</a>
        <button id="theme-toggle-btn" class="theme-switch">🌓 LIGHT MODE</button>
    </div>
    <div class="card">
        <div class="status-badge active">ACTIVE</div>
        <h1>%s</h1>
        <div class="meta">ID: %s</div>
        
        <div class="insight-header">
            <span style="color: var(--meta-color);">// AI_INSIGHT</span>
            <span style="color: var(--accent);">[ %s ]</span>
        </div>
        <div class="insight">%s</div>
        
        %s
        
        <div class="proof-box">
            <div style="font-size: 0.8rem; color: var(--accent); font-weight: bold; margin-bottom: 1rem;">// CRYPTOGRAPHIC INTEGRITY PROOF</div>
            <div class="proof-row">
                <div class="proof-label">ISSUER DID</div>
                <div class="proof-value">%s</div>
            </div>
            <div class="proof-row">
                <div class="proof-label">VC HASH</div>
                <div class="proof-value">%s</div>
            </div>
            <div class="proof-row">
                <div class="proof-label">PREV VC HASH</div>
                <div class="proof-value">%s</div>
            </div>
            <div class="proof-row">
                <div class="proof-label">SIGNATURE</div>
                <div class="proof-value">%s</div>
            </div>
        </div>
    </div>
    
    <a href="?format=json" class="btn-raw" target="_blank">[ VIEW RAW JSON ↗ ]</a>

    <script>
        const urlParams = new URLSearchParams(window.location.search);
        const themeParam = urlParams.get('theme');
        const savedTheme = localStorage.getItem('verihash-theme-preference');
        const body = document.body;
        const btn = document.getElementById('theme-toggle-btn');

        function setTheme(isLight) {
            if (isLight) {
                body.classList.add('theme-light');
                if (btn) btn.innerHTML = '🌓 DARK MODE';
            } else {
                body.classList.remove('theme-light');
                if (btn) btn.innerHTML = '🌓 LIGHT MODE';
            }
        }

        const isLight = themeParam === 'light' || (!themeParam && savedTheme === 'light');
        setTheme(isLight);

        if (btn) {
            btn.addEventListener('click', () => {
                const nowLight = !body.classList.contains('theme-light');
                setTheme(nowLight);
                localStorage.setItem('verihash-theme-preference', nowLight ? 'light' : 'dark');
            });
        }
    </script>
</body>
</html>`,
		html.EscapeString(title),
		url.PathEscape(strings.TrimPrefix(did, "did:key:")),
		html.EscapeString(title),
		html.EscapeString(vc.VCID),
		html.EscapeString(engineName),
		strings.ReplaceAll(html.EscapeString(vc.AIInsight), "\n", "<br>"),
		tagsHtml,
		html.EscapeString(did),
		html.EscapeString(vc.VCHash),
		html.EscapeString(vc.PrevVCHash),
		html.EscapeString(vc.ProofSignature),
	)

	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(htmlStr))
}

func renderTombstoneHTML(c *gin.Context, did, vcID, tombType, revokedAt, signature, origHash, prevHash string) {
	label := "WITHDRAWN"
	desc := "This credential has been withdrawn from public index by the issuer. The content has been retracted, but the block hash remains continuous on the chain."
	badgeClass := "withdrawn"
	if tombType == "destroy" || tombType == "destroyed" {
		label = "DESTROYED"
		desc = "This credential has been permanently destroyed and revoked by the issuer. The content is gone, but the cryptographic hash has been preserved to audit the block history."
		badgeClass = "destroyed"
	}

	htmlStr := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Revoked Credential - VeriHash</title>
    <style>
        :root {
            /* Default to Dark - Destroyed variables */
            --bg-color: #0b0e14;
            --text-color: #c0d0e0;
            --font-family: monospace;
            --meta-color: #666;
            --accent: #ff4466;
            --accent-dim: rgba(255, 68, 102, 0.15);
            --accent-bg: rgba(255, 68, 102, 0.02);
            --card-shadow: 0 0 20px rgba(255, 68, 102, 0.02);
            --proof-label: #555;
            --proof-value: #666;
            --back-link: #888;
            --back-hover: #ff4466;
            --btn-border: rgba(255, 68, 102, 0.3);
            --btn-color: #ff4466;
            --btn-bg: rgba(255, 68, 102, 0.03);
            --btn-hover-bg: rgba(255, 68, 102, 0.15);
            --btn-hover-color: #fff;
            --btn-hover-border: #ff4466;
        }

        body.withdrawn-theme {
            --accent: #8888aa;
            --accent-dim: rgba(136, 136, 170, 0.15);
            --accent-bg: rgba(136, 136, 170, 0.02);
            --card-shadow: 0 0 20px rgba(136, 136, 170, 0.02);
            --back-hover: #8888aa;
            --btn-border: rgba(136, 136, 170, 0.3);
            --btn-color: #8888aa;
            --btn-bg: rgba(136, 136, 170, 0.03);
            --btn-hover-bg: rgba(136, 136, 170, 0.15);
            --btn-hover-border: #8888aa;
        }

        body.theme-light.destroyed-theme {
            --bg-color: #f8fafc;
            --text-color: #1e293b;
            --font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            --meta-color: #64748b;
            --accent: #dc2626;
            --accent-dim: rgba(220, 38, 38, 0.15);
            --accent-bg: #fffefe;
            --card-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05), 0 2px 4px -1px rgba(0, 0, 0, 0.03);
            --proof-label: #64748b;
            --proof-value: #334155;
            --back-link: #64748b;
            --back-hover: #dc2626;
            --btn-border: #dc2626;
            --btn-color: #dc2626;
            --btn-bg: rgba(220, 38, 38, 0.02);
            --btn-hover-bg: #dc2626;
            --btn-hover-color: #ffffff;
            --btn-hover-border: #dc2626;
        }

        body.theme-light.withdrawn-theme {
            --bg-color: #f8fafc;
            --text-color: #1e293b;
            --font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            --meta-color: #64748b;
            --accent: #475569;
            --accent-dim: rgba(71, 85, 105, 0.15);
            --accent-bg: #fffefe;
            --card-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05), 0 2px 4px -1px rgba(0, 0, 0, 0.03);
            --proof-label: #64748b;
            --proof-value: #334155;
            --back-link: #64748b;
            --back-hover: #475569;
            --btn-border: #475569;
            --btn-color: #475569;
            --btn-bg: rgba(71, 85, 105, 0.02);
            --btn-hover-bg: #475569;
            --btn-hover-color: #ffffff;
            --btn-hover-border: #475569;
        }

        body { background: var(--bg-color); color: var(--text-color); font-family: var(--font-family); padding: 2rem; max-width: 800px; margin: 0 auto; transition: background 0.25s, color 0.25s; }
        h1 { color: var(--accent); font-size: 1.4rem; letter-spacing: 0.05em; margin-bottom: 0.5rem; }
        .meta { font-size: 0.75rem; color: var(--meta-color); margin-bottom: 20px; border-bottom: 1px dashed var(--accent-dim); padding-bottom: 8px; word-break: break-all; }
        body.theme-light .meta { border-bottom: 1px solid var(--accent-dim); }
        .card { border: 1px solid var(--btn-border); padding: 2rem; background: var(--accent-bg); border-radius: 6px; position: relative; box-shadow: var(--card-shadow); transition: background 0.25s, border-color 0.25s; }
        .status-badge { position: absolute; top: 1.5rem; right: 1.5rem; font-size: 0.72rem; padding: 3px 8px; border-radius: 3px; font-weight: bold; border: 1px solid; letter-spacing: 0.05em; }
        .status-badge.destroyed { border-color: var(--accent); color: var(--accent); background: var(--accent-dim); }
        .status-badge.withdrawn { border-color: var(--accent); color: var(--accent); background: var(--accent-dim); }
        .tombstone-msg { color: var(--accent); background: var(--accent-dim); border: 1px solid var(--accent-dim); padding: 1.25rem; border-radius: 4px; line-height: 1.6; margin-top: 1.5rem; font-size: 0.88rem; }
        body.theme-light .tombstone-msg { background: rgba(220, 38, 38, 0.03); border: 1px solid rgba(220, 38, 38, 0.1); }
        body.theme-light.withdrawn-theme .tombstone-msg { background: rgba(71, 85, 105, 0.03); border: 1px solid rgba(71, 85, 105, 0.1); }
        .proof-box { margin-top: 2.5rem; border-top: 1px solid var(--accent-dim); padding-top: 1.5rem; font-size: 0.75rem; }
        .proof-row { margin-bottom: 0.6rem; display: flex; flex-flow: row wrap; }
        .proof-label { color: var(--proof-label); width: 140px; text-transform: uppercase; font-size: 0.7rem; letter-spacing: 0.05em; }
        .proof-value { color: var(--proof-value); flex: 1; word-break: break-all; font-family: monospace; }
        .back-link { color: var(--back-link); text-decoration: none; font-size: 0.8rem; display: inline-flex; align-items: center; gap: 6px; transition: color 0.2s; }
        .back-link:hover { color: var(--back-hover); }
        .btn-raw { display: inline-block; font-size: 0.78rem; border: 1px solid var(--btn-border); padding: 6px 14px; border-radius: 4px; color: var(--btn-color); text-decoration: none; background: var(--btn-bg); transition: all 0.2s ease; margin-top: 1.5rem; }
        .btn-raw:hover { background: var(--btn-hover-bg); color: var(--btn-hover-color); border-color: var(--btn-hover-border); }

        .header-row { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; margin-bottom: 1.5rem; gap: 10px; }
        .theme-switch {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            background: rgba(255, 68, 102, 0.08);
            border: 1px solid rgba(255, 68, 102, 0.3);
            color: #ff4466;
            font-size: 0.7rem;
            font-family: monospace;
            padding: 4px 10px;
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.2s ease;
            text-decoration: none;
            letter-spacing: 0.05em;
        }
        .theme-switch:hover {
            background: rgba(255, 68, 102, 0.2);
            color: #fff;
            border-color: #ff4466;
        }
        body.withdrawn-theme .theme-switch {
            background: rgba(136, 136, 170, 0.08);
            border: 1px solid rgba(136, 136, 170, 0.3);
            color: #8888aa;
        }
        body.withdrawn-theme .theme-switch:hover {
            background: rgba(136, 136, 170, 0.2);
            color: #fff;
            border-color: #8888aa;
        }
        body.theme-light .theme-switch {
            background: rgba(2, 132, 199, 0.08);
            border: 1px solid rgba(2, 132, 199, 0.3);
            color: #0284c7;
        }
        body.theme-light .theme-switch:hover {
            background: #0284c7;
            color: #fff;
        }
    </style>
</head>
<body class="%s-theme">
    <div class="header-row">
        <a href="/u/%s" class="back-link">&lt; Back to Issuer Profile</a>
        <button id="theme-toggle-btn" class="theme-switch">🌓 LIGHT MODE</button>
    </div>
    <div class="card">
        <div class="status-badge %s">%s</div>
        <h1>CREDENTIAL %s</h1>
        <div class="meta">ID: %s</div>
        
        <div class="tombstone-msg">
            %s
        </div>
        
        <div class="proof-box">
            <div style="font-size: 0.8rem; color: var(--accent); font-weight: bold; margin-bottom: 1rem;">// CRYPTOGRAPHIC REVOCATION PROOF</div>
            <div class="proof-row">
                <div class="proof-label">ISSUER DID</div>
                <div class="proof-value">%s</div>
            </div>
            <div class="proof-row">
                <div class="proof-label">ORIGINAL VC HASH</div>
                <div class="proof-value">%s</div>
            </div>
            <div class="proof-row">
                <div class="proof-label">PREV VC HASH</div>
                <div class="proof-value">%s</div>
            </div>
            <div class="proof-row">
                <div class="proof-label">REVOKED AT</div>
                <div class="proof-value">%s</div>
            </div>
            <div class="proof-row">
                <div class="proof-label">REVOCATION SIG</div>
                <div class="proof-value">%s</div>
            </div>
        </div>
    </div>
    
    <a href="?format=json" class="btn-raw" target="_blank">[ VIEW RAW TOMBSTONE ↗ ]</a>

    <script>
        const urlParams = new URLSearchParams(window.location.search);
        const themeParam = urlParams.get('theme');
        const savedTheme = localStorage.getItem('verihash-theme-preference');
        const body = document.body;
        const btn = document.getElementById('theme-toggle-btn');

        function setTheme(isLight) {
            if (isLight) {
                body.classList.add('theme-light');
                if (btn) btn.innerHTML = '🌓 DARK MODE';
            } else {
                body.classList.remove('theme-light');
                if (btn) btn.innerHTML = '🌓 LIGHT MODE';
            }
        }

        const isLight = themeParam === 'light' || (!themeParam && savedTheme === 'light');
        setTheme(isLight);

        if (btn) {
            btn.addEventListener('click', () => {
                const nowLight = !body.classList.contains('theme-light');
                setTheme(nowLight);
                localStorage.setItem('verihash-theme-preference', nowLight ? 'light' : 'dark');
            });
        }
    </script>
</body>
</html>`,
		badgeClass,
		url.PathEscape(strings.TrimPrefix(did, "did:key:")),
		badgeClass,
		label,
		label,
		html.EscapeString(vcID),
		html.EscapeString(desc),
		html.EscapeString(did),
		html.EscapeString(origHash),
		html.EscapeString(prevHash),
		html.EscapeString(revokedAt),
		html.EscapeString(signature),
	)

	c.Data(http.StatusGone, "text/html; charset=utf-8", []byte(htmlStr))
}
