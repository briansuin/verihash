package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

type VeriHashNodeBroadcaster struct {
	nodeURL string
	privKey ed25519.PrivateKey
	pubKey  ed25519.PublicKey
	client  *http.Client
}

func NewVeriHashNodeBroadcaster(nodeURL string, privKey ed25519.PrivateKey, pubKey ed25519.PublicKey) *VeriHashNodeBroadcaster {
	if nodeURL == "" {
		nodeURL = "https://verihash.org"
	}
	return &VeriHashNodeBroadcaster{
		nodeURL: strings.TrimRight(nodeURL, "/"),
		privKey: privKey,
		pubKey:  pubKey,
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

func (v *VeriHashNodeBroadcaster) Channel() string {
	return "verihash_org"
}

// signRequest generates the identical "VERIHASH-PUBLISH-V1" signature expected by the server
func (v *VeriHashNodeBroadcaster) signRequest(payload []byte, timestamp, nonce string) string {
	did := pubKeyToDIDKey(v.pubKey)
	hash := sha256.Sum256(payload)
	msg := fmt.Sprintf(
		"VERIHASH-PUBLISH-V1\n%s\n%s\n%s\n%s",
		did,
		timestamp,
		nonce,
		hex.EncodeToString(hash[:]),
	)
	sig := ed25519.Sign(v.privKey, []byte(msg))
	return hex.EncodeToString(sig)
}

func (v *VeriHashNodeBroadcaster) Publish(payload BroadcastPayload) (remoteID, remoteURL string, err error) {
	if v.privKey == nil {
		return "", "", fmt.Errorf("wallet locked: cannot sign broadcast request")
	}

	// Transform BroadcastPayload to the PublicCredentialPayload structure expected by the node
	publicPayload := map[string]interface{}{
		"document_type":   "verihash_credential",
		"schema_version":  "0.1",
		"vc_id":           payload.VCID,
		"issuer":          payload.Issuer,
		"issued_at":       payload.IssuedAt,
		"title":           payload.PublicTitle,
		"ai_insight":      payload.AIInsight,
		"ai_engine":       payload.AIEngine,
		"skill_tags":      payload.SkillTags,
		"vc_hash":         payload.VCHash,
		"prev_vc_hash":    payload.PrevVCHash,
		"proof_signature": payload.Signature,
	}

	payloadBytes, err := json.Marshal(publicPayload)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	timestamp := time.Now().UTC().Format(time.RFC3339)
	nonce := uuid.New().String()
	did := pubKeyToDIDKey(v.pubKey)
	sigHex := v.signRequest(payloadBytes, timestamp, nonce)

	reqBody := map[string]interface{}{
		"did":       did,
		"timestamp": timestamp,
		"nonce":     nonce,
		"payload":   json.RawMessage(payloadBytes),
		"signature": sigHex,
	}

	reqBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", "", err
	}

	req, err := http.NewRequest("POST", v.nodeURL+"/v1/credentials", bytes.NewReader(reqBytes))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := v.client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("network error: %w", err)
	}
	defer resp.Body.Close()

	respBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("node returned HTTP %d: %s", resp.StatusCode, string(respBytes))
	}

	var result struct {
		URL  string `json:"url"`
		VCID string `json:"vc_id"`
	}
	if err := json.Unmarshal(respBytes, &result); err != nil {
		return "", "", fmt.Errorf("failed to parse node response: %w", err)
	}

	log.Printf("[BROADCAST] Successfully published to VeriHash Node: %s", result.VCID)
	// Return VCID as remoteID for UPSERTs in the future
	return result.VCID, v.nodeURL + result.URL, nil
}

func (v *VeriHashNodeBroadcaster) Update(remoteID string, payload BroadcastPayload) (remoteURL string, notFound bool, err error) {
	// The verihash.org node UPSERTs automatically on POST via SQLite ON CONFLICT DO UPDATE.
	// So Update is exactly the same network call as Publish.
	_, url, err := v.Publish(payload)
	return url, false, err
}

func (v *VeriHashNodeBroadcaster) Revoke(remoteID string, tombstone TombstonePayload) (remoteURL string, err error) {
	if v.privKey == nil {
		return "", fmt.Errorf("wallet locked: cannot sign broadcast request")
	}

	payloadBytes, err := json.Marshal(tombstone)
	if err != nil {
		return "", fmt.Errorf("failed to marshal tombstone: %w", err)
	}

	timestamp := time.Now().UTC().Format(time.RFC3339)
	nonce := uuid.New().String()
	did := pubKeyToDIDKey(v.pubKey)
	sigHex := v.signRequest(payloadBytes, timestamp, nonce)

	reqBody := map[string]interface{}{
		"did":       did,
		"timestamp": timestamp,
		"nonce":     nonce,
		"payload":   json.RawMessage(payloadBytes),
		"signature": sigHex,
	}

	reqBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", v.nodeURL+"/v1/revoke", bytes.NewReader(reqBytes))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := v.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("network error: %w", err)
	}
	defer resp.Body.Close()

	respBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("node returned HTTP %d: %s", resp.StatusCode, string(respBytes))
	}

	log.Printf("[BROADCAST] Successfully revoked on VeriHash Node: %s", tombstone.VCID)
	return v.nodeURL + "/u/" + did, nil
}

func (v *VeriHashNodeBroadcaster) Delete(remoteID string) error {
	// The node does not support physical deletion of ledgers (blockchain semantics)
	return nil
}

func (v *VeriHashNodeBroadcaster) PublishProfile(profileJSON []byte) error {
	if v.privKey == nil {
		return fmt.Errorf("wallet locked: cannot sign broadcast request")
	}

	timestamp := time.Now().UTC().Format(time.RFC3339)
	nonce := uuid.New().String()
	did := pubKeyToDIDKey(v.pubKey)
	sigHex := v.signRequest(profileJSON, timestamp, nonce)

	reqBody := map[string]interface{}{
		"did":       did,
		"timestamp": timestamp,
		"nonce":     nonce,
		"payload":   json.RawMessage(profileJSON),
		"signature": sigHex,
	}

	reqBytes, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", v.nodeURL+"/v1/profile", bytes.NewReader(reqBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("network error: %w", err)
	}
	defer resp.Body.Close()

	respBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("node returned HTTP %d: %s", resp.StatusCode, string(respBytes))
	}

	log.Printf("[BROADCAST] Successfully published profile to VeriHash Node: %s", did)
	return nil
}
