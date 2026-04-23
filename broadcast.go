package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"strings"
	"time"
)

// ── BroadcastPayload ──────────────────────────────────────────────────────────
//
// BroadcastPayload is the ONLY data structure that leaves the local machine
// via any broadcast channel. It is a scrubbed, public-safe subset of the full
// internal VC. Local file paths, raw diffs, and private metadata are NEVER
// included here. All public exports (Gist, Nostr, future channels) derive from
// this struct — never from full_vc_json directly.

// BroadcastPayload holds the public-safe fields extracted from a credential.
type BroadcastPayload struct {
	VCID        string   `json:"vc_id"`
	Issuer      string   `json:"issuer"`
	IssuedAt    string   `json:"issued_at"`
	ProjectName string   `json:"project_name"`
	AIInsight   string   `json:"ai_insight"`
	SkillTags   []string `json:"skill_tags"`
	VCHash      string   `json:"vc_hash"`
	Signature   string   `json:"proof_signature"`
	AIEngine    string   `json:"ai_engine,omitempty"`
}

// NewBroadcastPayload constructs a sanitized BroadcastPayload from the DB.
// It reads the full VC JSON, parses it, and extracts only the public fields.
// Returns an error if the credential is not found or cannot be parsed.
func NewBroadcastPayload(db *VeriHashDB, vcID string) (*BroadcastPayload, error) {
	var fullJSON, vcHash string
	err := db.conn.QueryRow(
		`SELECT full_vc_json, COALESCE(vc_hash,'') FROM session_credentials WHERE vc_id = ?`, vcID,
	).Scan(&fullJSON, &vcHash)
	if err != nil {
		return nil, fmt.Errorf("credential not found: %w", err)
	}

	var vc VCSchema
	if err := json.Unmarshal([]byte(fullJSON), &vc); err != nil {
		return nil, fmt.Errorf("failed to parse VC JSON: %w", err)
	}

	pow := vc.CredentialSubject.ProofOfWork

	// Parse skill tags — stored as a comma-separated string in the DB
	var tags []string
	rawTags := strings.TrimSpace(pow.SkillTags)
	if rawTags != "" {
		for _, t := range strings.Split(rawTags, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				tags = append(tags, t)
			}
		}
	}

	return &BroadcastPayload{
		VCID:        vc.ID,
		Issuer:      vc.Issuer,
		IssuedAt:    vc.IssuanceDate,
		ProjectName: pow.ProjectContext,
		AIInsight:   pow.AIEvaluation,
		SkillTags:   tags,
		VCHash:      vcHash,
		Signature:   vc.Proof.ProofValue,
		AIEngine:    pow.AIEngine,
	}, nil
}

// ── Broadcaster Interface ─────────────────────────────────────────────────────

// Broadcaster is the contract every broadcast channel must implement.
// Channels are completely decoupled from the internal VC structure — they only
// receive a BroadcastPayload, keeping the broadcast layer a clean abstraction.
type Broadcaster interface {
	// Channel returns the canonical channel name, e.g. "gist" or "nostr".
	Channel() string
	// Publish sends the payload to the channel and returns the remote ID and URL.
	Publish(payload BroadcastPayload) (remoteID, remoteURL string, err error)
	// Revoke attempts to physically delete the broadcast artifact by its remote ID.
	Revoke(remoteID string) error
}

// ── BroadcastManager ─────────────────────────────────────────────────────────

const (
	maxBroadcastAttempts = 5
	baseRetryDelay       = 10 * time.Second // initial backoff duration
)

// BroadcastManager orchestrates async broadcasting across all registered channels.
// It writes status to broadcast_publications and never rolls back the local ledger
// on network failure.
type BroadcastManager struct {
	broadcasters map[string]Broadcaster
	db           *VeriHashDB
}

// NewBroadcastManager creates an empty BroadcastManager.
func NewBroadcastManager(db *VeriHashDB) *BroadcastManager {
	return &BroadcastManager{
		broadcasters: make(map[string]Broadcaster),
		db:           db,
	}
}

// RegisterBroadcaster adds a broadcaster for the given channel.
// Calling this with an already-registered channel replaces the old implementation.
func (bm *BroadcastManager) RegisterBroadcaster(b Broadcaster) {
	bm.broadcasters[b.Channel()] = b
}

// BroadcastVC queues the VC for broadcast on all registered channels and fires
// them off concurrently in goroutines. It is intentionally fire-and-forget from
// the caller's perspective; the DB is the source of truth for status.
func (bm *BroadcastManager) BroadcastVC(vcID string) {
	payload, err := NewBroadcastPayload(bm.db, vcID)
	if err != nil {
		log.Printf("[BROADCAST] Failed to build payload for %s: %v", vcID, err)
		return
	}

	for _, b := range bm.broadcasters {
		channel := b.Channel()
		// Upsert the broadcast job (creates "pending" row or re-queues failed ones)
		if err := bm.db.UpsertBroadcastJob(vcID, channel); err != nil {
			log.Printf("[BROADCAST] DB upsert failed for (%s, %s): %v", vcID, channel, err)
			continue
		}
		// Launch each channel's publish in a separate goroutine
		go bm.runWithRetry(b, *payload)
	}
}

// runWithRetry executes Publish with exponential backoff up to maxBroadcastAttempts.
// The local DB status is the only thing updated; the local ledger is never touched.
func (bm *BroadcastManager) runWithRetry(b Broadcaster, payload BroadcastPayload) {
	vcID := payload.VCID
	channel := b.Channel()

	for attempt := 1; attempt <= maxBroadcastAttempts; attempt++ {
		// Mark as "publishing" so the UI can show an in-progress state
		_ = bm.db.UpdateBroadcastStatus(vcID, channel, "publishing", "", "", "")

		remoteID, remoteURL, err := b.Publish(payload)
		if err == nil {
			_ = bm.db.UpdateBroadcastStatus(vcID, channel, "success", remoteID, remoteURL, "")
			log.Printf("[BROADCAST] ✓ %s → %s: %s", vcID[:20]+"...", channel, remoteURL)
			return
		}

		// Exponential backoff: 10s, 20s, 40s, 80s, 160s
		backoff := time.Duration(float64(baseRetryDelay) * math.Pow(2, float64(attempt-1)))
		lastErr := err.Error()
		log.Printf("[BROADCAST] ✗ %s → %s (attempt %d/%d): %s. Retrying in %v",
			vcID[:min(20, len(vcID))]+"...", channel, attempt, maxBroadcastAttempts, lastErr, backoff)

		_ = bm.db.UpdateBroadcastStatus(vcID, channel, "failed", "", "", lastErr)

		if attempt < maxBroadcastAttempts {
			time.Sleep(backoff)
		}
	}

	log.Printf("[BROADCAST] Gave up broadcasting %s → %s after %d attempts", vcID, channel, maxBroadcastAttempts)
}

// RevokeBroadcast physically deletes the remote artifact for the given channel
// and marks the broadcast record as revoked in the DB.
func (bm *BroadcastManager) RevokeBroadcast(vcID, channel string) error {
	b, ok := bm.broadcasters[channel]
	if !ok {
		return fmt.Errorf("no broadcaster registered for channel %q", channel)
	}

	// Fetch the remote_id from DB
	pubs, err := bm.db.GetBroadcastsByVC(vcID)
	if err != nil {
		return fmt.Errorf("DB lookup failed: %w", err)
	}
	var remoteID string
	for _, p := range pubs {
		if p.Channel == channel {
			remoteID = p.RemoteID
			break
		}
	}
	if remoteID == "" {
		return fmt.Errorf("no remote_id found for (%s, %s) — cannot revoke", vcID, channel)
	}

	if err := b.Revoke(remoteID); err != nil {
		return fmt.Errorf("remote revoke failed: %w", err)
	}

	return bm.db.UpdateBroadcastStatus(vcID, channel, "revoked", remoteID, "", "")
}

// min is a helper for Go versions before 1.21 which lack the built-in min().
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ── GitHubGistBroadcaster ────────────────────────────────────────────────────

const githubAPIBase = "https://api.github.com"

// GitHubGistBroadcaster implements the Broadcaster interface for GitHub Gists.
// Each VC is published as a single, public Gist containing the BroadcastPayload JSON.
type GitHubGistBroadcaster struct {
	pat    string       // Personal Access Token with gist scope
	client *http.Client
}

// NewGitHubGistBroadcaster creates a broadcaster backed by a GitHub PAT.
func NewGitHubGistBroadcaster(pat string) *GitHubGistBroadcaster {
	return &GitHubGistBroadcaster{
		pat:    pat,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (g *GitHubGistBroadcaster) Channel() string { return "gist" }

// Publish creates a new public Gist containing the sanitized BroadcastPayload JSON.
// Returns the Gist ID and HTML URL on success.
func (g *GitHubGistBroadcaster) Publish(payload BroadcastPayload) (remoteID, remoteURL string, err error) {
	if g.pat == "" {
		return "", "", fmt.Errorf("GitHub PAT is not configured")
	}

	payloadBytes, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Gist file name: safe filename derived from vc_id
	fileName := strings.ReplaceAll(payload.VCID, ":", "_") + ".json"
	description := fmt.Sprintf("VeriHash VC — %s [%s]", payload.ProjectName, payload.IssuedAt[:10])

	body := map[string]interface{}{
		"description": description,
		"public":      true,
		"files": map[string]interface{}{
			fileName: map[string]string{
				"content": string(payloadBytes),
			},
		},
	}
	bodyBytes, _ := json.Marshal(body)

	req, err := http.NewRequest("POST", githubAPIBase+"/gists", bytes.NewReader(bodyBytes))
	if err != nil {
		return "", "", fmt.Errorf("request build failed: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+g.pat)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := g.client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		return "", "", fmt.Errorf("GitHub API error %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		ID      string `json:"id"`
		HTMLURL string `json:"html_url"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", "", fmt.Errorf("failed to parse GitHub response: %w", err)
	}

	return result.ID, result.HTMLURL, nil
}

// Revoke physically deletes a Gist by its ID.
func (g *GitHubGistBroadcaster) Revoke(gistID string) error {
	if g.pat == "" {
		return fmt.Errorf("GitHub PAT is not configured")
	}
	req, err := http.NewRequest("DELETE", githubAPIBase+"/gists/"+gistID, nil)
	if err != nil {
		return fmt.Errorf("request build failed: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+g.pat)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := g.client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	// 204 No Content = success; 404 = already deleted (idempotent)
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GitHub API error %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// ── ProfileIndex (Phase 4.5 Schema) ──────────────────────────────────────────

// ProfileIndexVC is a single entry in the recent_vcs list of a ProfileIndex.
type ProfileIndexVC struct {
	VCID     string `json:"vc_id"`
	Title    string `json:"title"`
	IssuedAt string `json:"issued_at"`
	GistURL  string `json:"gist_url"`
	Status   string `json:"status"` // "active" | "revoked"
}

// ProfileIndexRevocation records a revoked credential in the index.
type ProfileIndexRevocation struct {
	VCID             string `json:"vc_id"`
	RevokedAt        string `json:"revoked_at"`
	TombstoneGistURL string `json:"tombstone_gist_url"`
}

// ProfileIndex is the public root index file (verihash_profile_index.json).
// It is the single source of truth for external resolvers and the Ask VeriHash
// query layer. Schema version 0.1.
type ProfileIndex struct {
	SchemaVersion string                   `json:"schema_version"`
	DID           string                   `json:"did"`
	DisplayName   string                   `json:"display_name"`
	UpdatedAt     string                   `json:"updated_at"`
	SkillSummary  []string                 `json:"skill_summary"`
	RecentVCs     []ProfileIndexVC         `json:"recent_vcs"`
	Revocations   []ProfileIndexRevocation `json:"revocations"`
}

// GenerateProfileIndex builds the current ProfileIndex by joining session_credentials
// with broadcast_publications. Only VCs that have been successfully broadcast to the
// "gist" channel are included in recent_vcs.
func (db *VeriHashDB) GenerateProfileIndex(did string) (*ProfileIndex, error) {
	rows, err := db.conn.Query(`
		SELECT
			sc.vc_id,
			sc.project_context,
			sc.ai_insight,
			sc.skill_tags,
			sc.timestamp,
			sc.status,
			COALESCE(bp.remote_url, '') AS gist_url,
			COALESCE(bp.status, '')     AS pub_status
		FROM session_credentials sc
		LEFT JOIN broadcast_publications bp
			ON bp.vc_id = sc.vc_id AND bp.channel = 'gist'
		ORDER BY sc.timestamp DESC
		LIMIT 50
	`)
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}
	defer rows.Close()

	index := &ProfileIndex{
		SchemaVersion: "0.1",
		DID:           did,
		UpdatedAt:     time.Now().UTC().Format(time.RFC3339),
		RecentVCs:     []ProfileIndexVC{},
		Revocations:   []ProfileIndexRevocation{},
	}

	skillSet := make(map[string]struct{})

	for rows.Next() {
		var vcID, projectCtx, aiInsight, skillTagsStr, gistURL, pubStatus string
		var ts float64
		var credStatus int
		if err := rows.Scan(&vcID, &projectCtx, &aiInsight, &skillTagsStr, &ts, &credStatus, &gistURL, &pubStatus); err != nil {
			continue
		}

		// Collect unique skill tags for the summary
		for _, tag := range strings.Split(skillTagsStr, ",") {
			tag = strings.TrimSpace(tag)
			if tag != "" {
				skillSet[tag] = struct{}{}
			}
		}

		// Derive a title from the first sentence of AI insight (≤80 chars)
		title := projectCtx
		if aiInsight != "" {
			first := strings.SplitN(aiInsight, ".", 2)[0]
			if len(first) > 0 && len(first) <= 120 {
				title = strings.TrimSpace(first)
			}
		}

		issuedAt := time.Unix(int64(ts), 0).UTC().Format(time.RFC3339)

		if credStatus == 0 {
			// Revoked credential
			index.Revocations = append(index.Revocations, ProfileIndexRevocation{
				VCID:             vcID,
				RevokedAt:        issuedAt,
				TombstoneGistURL: gistURL,
			})
		} else if pubStatus == "success" {
			// Active, publicly broadcast credential
			index.RecentVCs = append(index.RecentVCs, ProfileIndexVC{
				VCID:     vcID,
				Title:    title,
				IssuedAt: issuedAt,
				GistURL:  gistURL,
				Status:   "active",
			})
		}
	}

	// Flatten skill set to a sorted slice
	for tag := range skillSet {
		index.SkillSummary = append(index.SkillSummary, tag)
	}

	return index, nil
}
