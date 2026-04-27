package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"strings"
	"sync"
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
// PRIVACY: project names, file names, and workspace paths are intentionally
// excluded — they can contain client names, contract titles, or other PII.
type BroadcastPayload struct {
	VCID      string   `json:"vc_id"`
	Issuer    string   `json:"issuer"`
	IssuedAt  string   `json:"issued_at"`
	AIInsight string   `json:"ai_insight"`
	SkillTags []string `json:"skill_tags"`
	VCHash    string   `json:"vc_hash"`
	Signature   string   `json:"proof_signature"`
	AIEngine    string   `json:"ai_engine,omitempty"`
	PublicTitle string   `json:"public_title,omitempty"`
}

// TombstonePayload carries the data needed to publish an in-place revocation
// notice on a broadcast artifact. The original VC file is renamed and its
// content is replaced with this signed tombstone — the Gist URL remains stable
// so all external references continue to resolve to the revocation notice.
type TombstonePayload struct {
	VCID            string `json:"vc_id"`
	IssuerDID       string `json:"issuer_did"`
	RevokedAt       string `json:"revoked_at"`       // RFC3339
	RevokeSignature string `json:"revoke_signature"` // Ed25519 hex
	OriginalVCHash  string `json:"original_vc_hash"` // SHA256 of the original VC
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

	// Parse skill tags — prefer the dedicated field (comma-separated).
	// For legacy credentials where skill_tags was never populated, fall back to
	// extracting tags directly from the AI evaluation text.
	tags := []string{} // never nil — ensures JSON [] not null
	rawTags := strings.TrimSpace(pow.SkillTags)
	if rawTags != "" {
		for _, t := range strings.Split(rawTags, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				tags = append(tags, t)
			}
		}
	} else if pow.AIEvaluation != "" {
		// Fallback: parse tags out of the AI insight text for old credentials
		tags = parseSkillTagsFromAI(pow.AIEvaluation)
	}

	return &BroadcastPayload{
		VCID:      vc.ID,
		Issuer:    vc.Issuer,
		IssuedAt:  vc.IssuanceDate,
		AIInsight: stripSkillTagsFromAI(pow.AIEvaluation), // strip tags section for legacy credentials
		SkillTags: tags,
		VCHash:    vcHash,
		Signature:   vc.Proof.ProofValue,
		AIEngine:    pow.AIEngine,
		PublicTitle: pow.PublicTitle,
	}, nil
}

// ── Broadcaster Interface ─────────────────────────────────────────────────────

// Broadcaster is the contract every broadcast channel must implement.
// Channels are completely decoupled from the internal VC structure — they only
// receive a BroadcastPayload, keeping the broadcast layer a clean abstraction.
type Broadcaster interface {
	// Channel returns the canonical channel name, e.g. "gist" or "nostr".
	Channel() string
	// Publish creates a new remote artifact and returns the remote ID and URL.
	Publish(payload BroadcastPayload) (remoteID, remoteURL string, err error)
	// Update replaces the content of an existing remote artifact identified by
	// remoteID. Returns notFound=true if the artifact no longer exists so the
	// caller can fall back to Publish.
	Update(remoteID string, payload BroadcastPayload) (remoteURL string, notFound bool, err error)
	// Revoke replaces the broadcast artifact content with a signed tombstone
	// notice in-place (PATCH). The remote URL never changes — external references
	// remain valid and resolve to the revocation notice. Returns the remote URL.
	Revoke(remoteID string, tombstone TombstonePayload) (remoteURL string, err error)
	// Delete physically removes the broadcast artifact. Used only when clearing
	// a broadcast record without revoking the credential (e.g. before re-publishing).
	Delete(remoteID string) error
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
	indexUpdater *IndexUpdater // Phase 4.5: notified on every successful Publish/Revoke
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

// runWithRetry executes Publish (or Update for re-broadcasts) with exponential
// backoff up to maxBroadcastAttempts. If the DB already has a remote_id for this
// VC+channel, Update is attempted first; a 404 (deleted Gist) transparently falls
// back to Publish so a fresh artifact is created.
func (bm *BroadcastManager) runWithRetry(b Broadcaster, payload BroadcastPayload) {
	vcID := payload.VCID
	channel := b.Channel()

	// Read existingRemoteID ONCE, BEFORE any status update that would clear it.
	// UpdateBroadcastStatus writes all fields including remote_id, so if we call
	// it with "" first we'd lose the preserved remote_id from ResetBroadcastForVC.
	var existingRemoteID string
	if pubs, dbErr := bm.db.GetBroadcastsByVC(vcID); dbErr == nil {
		for _, p := range pubs {
			if p.Channel == channel {
				existingRemoteID = p.RemoteID
				break
			}
		}
	}
	log.Printf("[BROADCAST] runWithRetry: vc=%s channel=%s existingRemoteID=%q",
		vcID[:min(20, len(vcID))]+"...", channel, existingRemoteID)

	for attempt := 1; attempt <= maxBroadcastAttempts; attempt++ {
		// Mark as "publishing" — pass existingRemoteID through so it is not overwritten with ""
		_ = bm.db.UpdateBroadcastStatus(vcID, channel, "publishing", existingRemoteID, "", "")

		var remoteID, remoteURL string
		var err error

		if existingRemoteID != "" {
			// Attempt to UPDATE the existing remote artifact in-place (PATCH)
			var notFound bool
			remoteURL, notFound, err = b.Update(existingRemoteID, payload)
			if err == nil {
				// Updated in-place — keep the same remote ID
				remoteID = existingRemoteID
			} else if notFound {
				// Remote was deleted by user — fall back to creating a new one
				log.Printf("[BROADCAST] Remote %s not found (deleted?), creating new artifact", existingRemoteID)
				remoteID, remoteURL, err = b.Publish(payload)
				if err == nil {
					// New artifact created — update existingRemoteID so retries also use PATCH
					existingRemoteID = remoteID
				}
			}
			// else: non-404 network error — err is set, fall through to retry logic
		} else {
			// First-time publish
			remoteID, remoteURL, err = b.Publish(payload)
			if err == nil {
				// Store so subsequent retries (if any) use PATCH not POST
				existingRemoteID = remoteID
			}
		}

		if err == nil {
			_ = bm.db.UpdateBroadcastStatus(vcID, channel, "success", remoteID, remoteURL, "")
			log.Printf("[BROADCAST] ✓ %s → %s: %s", vcID[:20]+"...", channel, remoteURL)
			// Signal the IndexUpdater so the public root index reflects the new VC
			if bm.indexUpdater != nil {
				bm.indexUpdater.Signal()
			}
			return
		}

		// Exponential backoff: 10s, 20s, 40s, 80s, 160s
		backoff := time.Duration(float64(baseRetryDelay) * math.Pow(2, float64(attempt-1)))
		lastErr := err.Error()
		log.Printf("[BROADCAST] ✗ %s → %s (attempt %d/%d): %s. Retrying in %v",
			vcID[:min(20, len(vcID))]+"...", channel, attempt, maxBroadcastAttempts, lastErr, backoff)

		// Preserve existingRemoteID on failure so the next attempt can still try PATCH
		_ = bm.db.UpdateBroadcastStatus(vcID, channel, "failed", existingRemoteID, "", lastErr)

		if attempt < maxBroadcastAttempts {
			time.Sleep(backoff)
		}
	}

	log.Printf("[BROADCAST] Gave up broadcasting %s → %s after %d attempts", vcID, channel, maxBroadcastAttempts)
}


// RevokeBroadcast stamps the remote broadcast artifact with an in-place tombstone
// (PATCH — the Gist URL stays alive) and marks the record as "revoked" in the DB.
// The remote_url is preserved because the Gist still exists as a tombstone.
func (bm *BroadcastManager) RevokeBroadcast(vcID, channel string, tombstone TombstonePayload) error {
	b, ok := bm.broadcasters[channel]
	if !ok {
		return fmt.Errorf("no broadcaster registered for channel %q", channel)
	}

	// Fetch the remote_id and existing URL from DB
	pubs, err := bm.db.GetBroadcastsByVC(vcID)
	if err != nil {
		return fmt.Errorf("DB lookup failed: %w", err)
	}
	var remoteID, existingURL string
	for _, p := range pubs {
		if p.Channel == channel {
			remoteID = p.RemoteID
			existingURL = p.RemoteURL
			break
		}
	}
	if remoteID == "" {
		return fmt.Errorf("no remote_id found for (%s, %s) — cannot revoke", vcID, channel)
	}

	remoteURL, err := b.Revoke(remoteID, tombstone)
	if err != nil {
		return fmt.Errorf("remote tombstone failed: %w", err)
	}

	// Preserve the URL — Gist still exists as a tombstone at the same address
	if remoteURL == "" {
		remoteURL = existingURL
	}
	if err := bm.db.UpdateBroadcastStatus(vcID, channel, "revoked", remoteID, remoteURL, ""); err != nil {
		return err
	}
	// Signal the IndexUpdater so the revocation appears in the public root index
	if bm.indexUpdater != nil {
		bm.indexUpdater.Signal()
	}
	return nil
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
	// Description: use explicit PublicTitle; fallback to generic
	description := payload.PublicTitle
	if description == "" {
		description = "VeriHash Credential"
	}

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

// Update patches an existing Gist in-place with fresh payload content.
// Returns notFound=true when the Gist has been deleted (HTTP 404) so the
// caller can transparently fall back to Publish.
func (g *GitHubGistBroadcaster) Update(gistID string, payload BroadcastPayload) (remoteURL string, notFound bool, err error) {
	if g.pat == "" {
		return "", false, fmt.Errorf("GitHub PAT is not configured")
	}

	payloadBytes, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return "", false, fmt.Errorf("failed to marshal payload: %w", err)
	}

	fileName := strings.ReplaceAll(payload.VCID, ":", "_") + ".json"
	// Description: skill tags + date — never project/file names (privacy)
	descLabel := payload.IssuedAt[:10]
	if len(payload.SkillTags) > 0 {
		descLabel = payload.SkillTags[0] + " [" + payload.IssuedAt[:10] + "]"
	}
	description := "VeriHash VC — " + descLabel

	body := map[string]interface{}{
		"description": description,
		"files": map[string]interface{}{
			fileName: map[string]string{
				"content": string(payloadBytes),
			},
		},
	}
	bodyBytes, _ := json.Marshal(body)

	req, err := http.NewRequest("PATCH", githubAPIBase+"/gists/"+gistID, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", false, fmt.Errorf("request build failed: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+g.pat)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := g.client.Do(req)
	if err != nil {
		return "", false, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// Gist was deleted on GitHub — caller should fall back to Publish
		return "", true, fmt.Errorf("gist %s not found (deleted)", gistID)
	}

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("GitHub API error %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		HTMLURL string `json:"html_url"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", false, fmt.Errorf("failed to parse GitHub PATCH response: %w", err)
	}

	log.Printf("[BROADCAST] Updated Gist %s in-place", gistID)
	return result.HTMLURL, false, nil
}

// Revoke replaces an existing Gist's content with a signed tombstone notice in-place.
// The original VC file is renamed to {vc_id}_REVOKED.json and overwritten with the
// tombstone JSON in a single PATCH call. The Gist URL never changes, so all external
// references remain valid and now resolve to the revocation notice.
func (g *GitHubGistBroadcaster) Revoke(gistID string, tombstone TombstonePayload) (remoteURL string, err error) {
	if g.pat == "" {
		return "", fmt.Errorf("GitHub PAT is not configured")
	}

	// Build the structured tombstone document
	tombstoneDoc := map[string]interface{}{
		"schema_version":   "0.1",
		"type":             "VeriHashRevocation",
		"vc_id":            tombstone.VCID,
		"issuer_did":       tombstone.IssuerDID,
		"revoked_at":       tombstone.RevokedAt,
		"revoke_signature": tombstone.RevokeSignature,
		"original_vc_hash": tombstone.OriginalVCHash,
		"note":             "This credential has been revoked by its issuer. The original broadcast payload has been replaced with this tombstone.",
	}
	tombstoneBytes, err := json.MarshalIndent(tombstoneDoc, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal tombstone: %w", err)
	}

	// Derive original filename (must match what Publish used) then rename to _REVOKED
	origFileName := strings.ReplaceAll(tombstone.VCID, ":", "_") + ".json"
	newFileName := strings.ReplaceAll(tombstone.VCID, ":", "_") + "_REVOKED.json"

	revokedDate := tombstone.RevokedAt
	if len(revokedDate) >= 10 {
		revokedDate = revokedDate[:10]
	}
	body := map[string]interface{}{
		"description": "⚠️ REVOKED [" + revokedDate + "] — VeriHash Credential",
		"files": map[string]interface{}{
			// Renaming a file in Gist: use the old name as key, set "filename" to new name
			origFileName: map[string]string{
				"filename": newFileName,
				"content":  string(tombstoneBytes),
			},
		},
	}
	bodyBytes, _ := json.Marshal(body)

	req, err := http.NewRequest("PATCH", githubAPIBase+"/gists/"+gistID, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("request build failed: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+g.pat)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := g.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API error %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		HTMLURL string `json:"html_url"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("failed to parse GitHub PATCH response: %w", err)
	}

	log.Printf("[BROADCAST] Gist %s stamped with tombstone in-place", gistID)
	return result.HTMLURL, nil
}

// Delete physically removes a Gist by its ID. Used only when clearing a broadcast
// record without revoking the credential (e.g. the user manually deletes a broadcast
// via DeleteBroadcastVC so they can re-publish from scratch).
func (g *GitHubGistBroadcaster) Delete(gistID string) error {
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

// ProfileInfo holds the optional public-facing identity fields set by the user.
// All fields are opt-in — empty means the user chose not to publish them.
type ProfileInfo struct {
	Name    string            `json:"name,omitempty"`
	Website string            `json:"website,omitempty"`
	Custom  map[string]string `json:"custom,omitempty"`
}

// ProfileIndex is the public root index file (verihash_profile_index.json).
// It is the single source of truth for external resolvers and the Ask VeriHash
// query layer. Schema version 0.2.
type ProfileIndex struct {
	SchemaVersion    string                   `json:"schema_version"`
	DocumentType     string                   `json:"document_type"`
	GeneratedBy      string                   `json:"generated_by"`
	GeneratorVersion string                   `json:"generator_version"`
	DID              string                   `json:"did"`
	DisplayName      string                   `json:"display_name"`
	Profile          ProfileInfo              `json:"profile"`
	UpdatedAt        string                   `json:"updated_at"`
	CredentialCount  int                      `json:"credential_count"`
	RevocationCount  int                      `json:"revocation_count"`
	SkillSummary     []string                 `json:"skill_summary"`
	RecentVCs        []ProfileIndexVC         `json:"recent_vcs"`
	Revocations      []ProfileIndexRevocation `json:"revocations"`
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
			COALESCE(bp.status, '')     AS pub_status,
			sc.full_vc_json
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
		SchemaVersion:    "0.2",
		DocumentType:     "VeriHashPublicRootIndex",
		GeneratedBy:      "VeriHash Nexus",
		GeneratorVersion: "0.3",
		DID:              did,
		UpdatedAt:        time.Now().UTC().Format(time.RFC3339),
		RecentVCs:        []ProfileIndexVC{},
		Revocations:      []ProfileIndexRevocation{},
	}

	skillSet := make(map[string]struct{})

	for rows.Next() {
		var vcID, projectCtx, aiInsight, skillTagsStr, gistURL, pubStatus, fullVCJSON string
		var ts float64
		var credStatus int
		if err := rows.Scan(&vcID, &projectCtx, &aiInsight, &skillTagsStr, &ts, &credStatus, &gistURL, &pubStatus, &fullVCJSON); err != nil {
			continue
		}

		// Collect unique skill tags for the summary
		for _, tag := range strings.Split(skillTagsStr, ",") {
			tag = strings.TrimSpace(tag)
			if tag != "" {
				skillSet[tag] = struct{}{}
			}
		}

		// Extract PublicTitle from full_vc_json if present
		title := ""
		var parsedVC VCSchema
		if jsonErr := json.Unmarshal([]byte(fullVCJSON), &parsedVC); jsonErr == nil {
			title = parsedVC.CredentialSubject.ProofOfWork.PublicTitle
		}

		if title == "" {
			title = "VeriHash Credential"
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

	// Populate counts
	index.CredentialCount = len(index.RecentVCs)
	index.RevocationCount = len(index.Revocations)

	return index, nil
}

// ── Index Gist helpers (Phase 4.5) ───────────────────────────────────────────

const indexFileName = "verihash_profile_index.json"

// CreateIndexGist publishes a brand-new public Gist containing the ProfileIndex.
// This is the Bootstrap step — called exactly once when index_gist_id is empty.
// The returned gistID must be persisted to verihash_config.json by the caller.
func (g *GitHubGistBroadcaster) CreateIndexGist(index *ProfileIndex) (gistID, gistURL string, err error) {
	if g.pat == "" {
		return "", "", fmt.Errorf("GitHub PAT is not configured")
	}
	content, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal index: %w", err)
	}
	body := map[string]interface{}{
		"description": "VeriHash Public Root Index — " + index.DID[:min(24, len(index.DID))],
		"public":      true,
		"files": map[string]interface{}{
			indexFileName: map[string]string{"content": string(content)},
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
		return "", "", fmt.Errorf("failed to parse response: %w", err)
	}
	log.Printf("[INDEX] Bootstrap: created root index Gist %s", result.ID)
	return result.ID, result.HTMLURL, nil
}

// PatchIndexGist updates the existing root index Gist in-place with fresh content.
// The Gist ID and URL never change — only the file content is overwritten.
// Returns notFound=true when the Gist has been deleted on GitHub so the caller
// can transparently fall back to CreateIndexGist (same pattern as VC Gist 404).
func (g *GitHubGistBroadcaster) PatchIndexGist(gistID string, index *ProfileIndex) (gistURL string, notFound bool, err error) {
	if g.pat == "" {
		return "", false, fmt.Errorf("GitHub PAT is not configured")
	}
	content, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return "", false, fmt.Errorf("failed to marshal index: %w", err)
	}
	body := map[string]interface{}{
		"description": "VeriHash Public Root Index — updated " + index.UpdatedAt[:10],
		"files": map[string]interface{}{
			indexFileName: map[string]string{"content": string(content)},
		},
	}
	bodyBytes, _ := json.Marshal(body)
	req, err := http.NewRequest("PATCH", githubAPIBase+"/gists/"+gistID, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", false, fmt.Errorf("request build failed: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+g.pat)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := g.client.Do(req)
	if err != nil {
		return "", false, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		// Index Gist was deleted on GitHub — caller should re-bootstrap
		return "", true, fmt.Errorf("index Gist %s not found (deleted externally)", gistID)
	}
	if resp.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("GitHub API error %d: %s", resp.StatusCode, string(respBody))
	}
	var result struct {
		HTMLURL string `json:"html_url"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", false, fmt.Errorf("failed to parse response: %w", err)
	}
	log.Printf("[INDEX] Root index Gist %s updated in-place", gistID)
	return result.HTMLURL, false, nil
}

// ── IndexUpdater (Phase 4.5 auto-sync worker) ────────────────────────────────

// IndexUpdater is a serialized, debounced background worker that keeps the
// public root index Gist in sync after every Mint and Revoke operation.
//
// Design:
//   - A buffered channel of size 1 acts as a "dirty flag". Any number of
//     concurrent callers can Signal() without blocking. Duplicate signals
//     within the debounce window are collapsed into a single update.
//   - A mutex prevents two updates from running in parallel (safety net).
//   - Bootstrap logic: if index_gist_id is absent from config, CreateIndexGist
//     is called once and the returned ID is persisted immediately.
type IndexUpdater struct {
	ch          chan struct{}
	mu          sync.Mutex
	db          *VeriHashDB
	broadcaster *GitHubGistBroadcaster
	cfgPath     string // path to verihash_config.json for persisting index_gist_id
	cancel      context.CancelFunc // cancels the Run goroutine
}

// NewIndexUpdater constructs an IndexUpdater ready to be started with Start().
func NewIndexUpdater(db *VeriHashDB, broadcaster *GitHubGistBroadcaster, cfgPath string) *IndexUpdater {
	return &IndexUpdater{
		ch:          make(chan struct{}, 1),
		db:          db,
		broadcaster: broadcaster,
		cfgPath:     cfgPath,
	}
}

// Start launches the background event loop in its own goroutine.
// It is idempotent — calling Start() on an already-running IndexUpdater is a no-op.
func (iu *IndexUpdater) Start() {
	iu.mu.Lock()
	defer iu.mu.Unlock()
	if iu.cancel != nil {
		return // already running
	}
	ctx, cancel := context.WithCancel(context.Background())
	iu.cancel = cancel
	go iu.Run(ctx)
}

// Stop signals the background goroutine to exit and waits for cleanup.
// After Stop() returns, it is safe to replace the DB file on Windows.
func (iu *IndexUpdater) Stop() {
	iu.mu.Lock()
	cancel := iu.cancel
	iu.cancel = nil
	iu.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// UpdateBroadcaster swaps the broadcaster (e.g. when the PAT changes at runtime).
func (iu *IndexUpdater) UpdateBroadcaster(b *GitHubGistBroadcaster) {
	iu.mu.Lock()
	defer iu.mu.Unlock()
	iu.broadcaster = b
}

// Signal enqueues an index update request. It never blocks — if an update is
// already queued, the duplicate signal is silently dropped (debounce).
func (iu *IndexUpdater) Signal() {
	select {
	case iu.ch <- struct{}{}:
	default: // already queued — drop duplicate
	}
}

// Run starts the background event loop. It blocks until ctx is cancelled and
// should be launched in its own goroutine at startup.
func (iu *IndexUpdater) Run(ctx context.Context) {
	const debounce = 4 * time.Second // wait for burst of rapid Mints to settle
	for {
		select {
		case <-ctx.Done():
			return
		case <-iu.ch:
			// Debounce: absorb any additional signals that arrive while we wait
			timer := time.NewTimer(debounce)
		drain:
			for {
				select {
				case <-iu.ch:
					// reset debounce window
					if !timer.Stop() {
						<-timer.C
					}
					timer.Reset(debounce)
				case <-timer.C:
					break drain
				case <-ctx.Done():
					timer.Stop()
					return
				}
			}
			// Serialize: only one update at a time
			iu.mu.Lock()
			iu.doUpdate()
			iu.mu.Unlock()
		}
	}
}

// doUpdate performs the actual index sync. Must be called with mu held.
func (iu *IndexUpdater) doUpdate() {
	// Read current config to get DID, display_name, and index_gist_id
	cfgBytes, err := os.ReadFile(iu.cfgPath)
	if err != nil {
		log.Printf("[INDEX] Cannot read config: %v", err)
		return
	}
	var cfg Config
	if err := json.Unmarshal(cfgBytes, &cfg); err != nil {
		log.Printf("[INDEX] Cannot parse config: %v", err)
		return
	}

	// Derive the DID from the broadcaster's perspective via the config
	// (DID is stored in node_identity.json; we read it here for the index)
	did := cfg.IndexGistID // will be overwritten below if empty — we need the DID separately
	_ = did

	// Read the DID from node_identity.json
	var identity struct {
		DID string `json:"did"`
	}
	if idBytes, err := os.ReadFile("node_identity.json"); err == nil {
		json.Unmarshal(idBytes, &identity)
	}
	if identity.DID == "" {
		log.Printf("[INDEX] DID not available yet — skipping index update")
		return
	}

	// Build fresh index snapshot from DB
	index, err := iu.db.GenerateProfileIndex(identity.DID)
	if err != nil {
		log.Printf("[INDEX] Failed to generate index: %v", err)
		return
	}
	// Inject optional public profile fields from config
	index.Profile = ProfileInfo{
		Name:    cfg.ProfileName,
		Website: cfg.ProfileWebsite,
		Custom:  cfg.ProfileCustom,
	}
	// display_name is derived from profile.name when set; falls back to legacy DisplayName field
	if cfg.ProfileName != "" {
		index.DisplayName = cfg.ProfileName
	} else {
		index.DisplayName = cfg.DisplayName
	}

	var gistID, gistURL string

	if cfg.IndexGistID == "" {
		// ── Bootstrap: first time, create the Gist ──────────────────────────
		gistID, gistURL, err = iu.broadcaster.CreateIndexGist(index)
		if err != nil {
			log.Printf("[INDEX] Bootstrap failed: %v", err)
			return
		}
		// Persist the new Gist ID and URL so subsequent runs use PATCH
		cfg.IndexGistID = gistID
		cfg.IndexGistURL = gistURL
		if out, merr := json.MarshalIndent(cfg, "", "  "); merr == nil {
			os.WriteFile(iu.cfgPath, out, 0644)
		}
		log.Printf("[INDEX] \u2713 Bootstrap complete. Root index pinned at %s", gistURL)
	} else {
		// ── Normal update: PATCH the existing Gist in-place ─────────────────
		gistURL, notFound, err := iu.broadcaster.PatchIndexGist(cfg.IndexGistID, index)
		if err != nil {
			if notFound {
				// Index Gist was deleted externally — clear stale ID and re-bootstrap
				log.Printf("[INDEX] Stale index_gist_id %s (Gist deleted) — clearing and re-bootstrapping", cfg.IndexGistID)
				cfg.IndexGistID = ""
				cfg.IndexGistURL = ""
				if out, merr := json.MarshalIndent(cfg, "", "  "); merr == nil {
					os.WriteFile(iu.cfgPath, out, 0644)
				}
				// Re-bootstrap with a fresh Gist
				newID, newURL, createErr := iu.broadcaster.CreateIndexGist(index)
				if createErr != nil {
					log.Printf("[INDEX] Re-bootstrap failed: %v", createErr)
					return
				}
				cfg.IndexGistID = newID
				cfg.IndexGistURL = newURL
				if out, merr := json.MarshalIndent(cfg, "", "  "); merr == nil {
					os.WriteFile(iu.cfgPath, out, 0644)
				}
				log.Printf("[INDEX] \u2713 Re-bootstrap complete. New root index at %s", newURL)
			} else {
				log.Printf("[INDEX] PATCH failed: %v", err)
			}
			return
		}
		// Update the stored URL (should be unchanged, but persist defensively)
		if gistURL != cfg.IndexGistURL && gistURL != "" {
			cfg.IndexGistURL = gistURL
			if out, merr := json.MarshalIndent(cfg, "", "  "); merr == nil {
				os.WriteFile(iu.cfgPath, out, 0644)
			}
		}
		log.Printf("[INDEX] \u2713 Root index updated at %s (%d VCs, %d revocations)",
			gistURL, len(index.RecentVCs), len(index.Revocations))
	}
}
