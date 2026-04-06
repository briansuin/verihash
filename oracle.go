package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// Snapshot represents a single row from file_snapshots
type Snapshot struct {
	ID           int
	Timestamp    float64
	FilePath     string
	ContentDiff  string
	CurrentHash  string
	PreviousHash string
}

// VCSchema represents the final Verifiable Credential structure
type VCSchema struct {
	Context           []string          `json:"@context"`
	ID                string            `json:"id"`
	Type              []string          `json:"type"`
	Issuer            string            `json:"issuer"`
	IssuanceDate      string            `json:"issuanceDate"`
	CredentialSubject CredentialSubject `json:"credentialSubject"`
	Proof             Proof             `json:"proof"`
}

type CredentialSubject struct {
	ID          string      `json:"id"`
	ProofOfWork ProofOfWork `json:"proofOfWork"`
}

type ProofOfWork struct {
	TimestampRange []float64 `json:"timestampRange"`
	FilePaths      []string  `json:"filePaths"`
	AIEvaluation   string    `json:"aiEvaluation"`
	HashChainRoot  string    `json:"hashChainRoot"`
}

type Proof struct {
	Type               string `json:"type"`
	Created            string `json:"created"`
	VerificationMode   string `json:"verificationMethod"`
	ProofPurpose       string `json:"proofPurpose"`
	PreviousVCHash     string `json:"previousVCHash,omitempty"`
	ProofValue         string `json:"proofValue"`
}

// VCSigningPayload is the canonical document that is signed.
// It covers all VC fields PLUS proof metadata (excluding proofValue),
// so the signature protects chain linkage and every header field.
type VCSigningPayload struct {
	Context           []string          `json:"@context"`
	ID                string            `json:"id"`
	Type              []string          `json:"type"`
	Issuer            string            `json:"issuer"`
	IssuanceDate      string            `json:"issuanceDate"`
	CredentialSubject CredentialSubject `json:"credentialSubject"`
	ProofMeta         VCSigningProofMeta `json:"proofMeta"`
}

type VCSigningProofMeta struct {
	Type               string `json:"type"`
	Created            string `json:"created"`
	VerificationMethod string `json:"verificationMethod"`
	ProofPurpose       string `json:"proofPurpose"`
	PreviousVCHash     string `json:"previousVCHash"`
}

// OllamaRequest represents the payload for Ollama
type OllamaRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

// OllamaResponse represents the response from Ollama
type OllamaResponse struct {
	Response string `json:"response"`
}

// MintCredential orchestrates the AI evaluation and VC signing
func MintCredential(ctx context.Context, db *VeriHashDB, pubKey ed25519.PublicKey, privKey ed25519.PrivateKey, engine, apiKey, baseURL string, selectedFilePaths []string, workspacePath string) string {
	runtime.EventsEmit(ctx, "log", map[string]string{"msg": "[ORACLE] Initializing Scoped Minting Sequence...", "type": "sys"})

	// 1. Fetch unminted snapshots explicitly restricted to client-selected files
	snapshots, err := db.GetSnapshotsByPaths(selectedFilePaths)
	if err != nil || len(snapshots) == 0 {
		runtime.EventsEmit(ctx, "log", map[string]string{"msg": "[ORACLE] Auto-initializing baseline context for virgin files...", "type": "sys"})
		// FALLBACK: Auto-mint virgin history to establish baseline context
		// IMPORTANT: Only store readable text, capped at 8KB per file to avoid DB bloat and token overflow
		const maxSeedBytes = 8 * 1024 // 8KB per file max
		for _, fPath := range selectedFilePaths {
			content, readErr := os.ReadFile(fPath)
			if readErr != nil {
				continue
			}
			// Skip binary files (PDFs, images, office docs) — only store their metadata
			excerpt := content
			if len(excerpt) > maxSeedBytes {
				excerpt = excerpt[:maxSeedBytes]
			}
			// Check if content is printable text (heuristic: <5% non-printable bytes)
			nonPrintable := 0
			checkLen := len(excerpt)
			if checkLen > 512 { checkLen = 512 }
			for _, b := range excerpt[:checkLen] {
				if b < 9 || (b > 13 && b < 32) || b == 127 {
					nonPrintable++
				}
			}
			var seedContent string
			if nonPrintable > checkLen/20 { // >5% non-printable = binary
				seedContent = fmt.Sprintf("[BINARY FILE: %s | SIZE: %d bytes]", fPath, len(content))
			} else {
				seedContent = string(excerpt)
			}
			db.CommitSnapshot(fPath, seedContent, privKey)
		}
		// Re-fetch now that they are seeded
		snapshots, _ = db.GetSnapshotsByPaths(selectedFilePaths)
		if len(snapshots) == 0 {
			runtime.EventsEmit(ctx, "log", map[string]string{"msg": "[ORACLE ERROR] Failed to establish physical AI context baseline.", "type": "err"})
			return `{"error": "No structural code found to hash"}`
		}
	}

	runtime.EventsEmit(ctx, "log", map[string]string{"msg": fmt.Sprintf("[ORACLE] Assembling %d physical blocks for tailored AI evaluation...", len(snapshots)), "type": "sys"})

	// 2. Prepare AI Context — strict token budget
	const maxCharsPerFile = 3000  // ~750 tokens per file
	const maxTotalChars  = 60000  // ~15K tokens total hard cap
	var contextBuilder strings.Builder
	var filePaths []string
	var minTs, maxTs float64 = snapshots[0].Timestamp, snapshots[0].Timestamp
	latestHash := snapshots[0].CurrentHash
	totalChars := 0

	for _, s := range snapshots {
		if s.Timestamp < minTs { minTs = s.Timestamp }
		if s.Timestamp > maxTs { maxTs = s.Timestamp }

		// Uniquify file paths
		found := false
		for _, f := range filePaths {
			if f == s.FilePath { found = true; break }
		}
		if !found {
			filePaths = append(filePaths, s.FilePath)
		}

		// Truncate each file's contribution
		excerpt := s.ContentDiff
		if len(excerpt) > maxCharsPerFile {
			excerpt = excerpt[:maxCharsPerFile] + "\n...[TRUNCATED]"
		}

		// Global cap: stop appending when budget is hit
		if totalChars+len(excerpt) > maxTotalChars {
			contextBuilder.WriteString(fmt.Sprintf("--- File: %s ---\n[BUDGET EXCEEDED — OMITTED]\n\n", s.FilePath))
			break
		}

		contextBuilder.WriteString(fmt.Sprintf("--- File: %s ---\nContent:\n%s\n\n", s.FilePath, excerpt))
		totalChars += len(excerpt)
	}

	runtime.EventsEmit(ctx, "log", map[string]string{"msg": fmt.Sprintf("[ORACLE] Context assembled: ~%d chars / %d files", totalChars, len(filePaths)), "type": "sys"})

	// 3. Call AI Engine
	prompt := fmt.Sprintf(`You are a legal document analyst and work-certification auditor. 
Review the following document file manifest and content excerpts, then summarize the work evidenced.
Output strictly in this format:
[WORKLOAD AUDIT]
(1-2 paragraph summary of the legal/professional work represented by these documents)
[VERIFIED SKILL TAGS]
* tag1
* tag2

FILE MANIFEST:
%s`, contextBuilder.String())

	var aiResult string

	// Parse provider and model from "provider:model-name" format
	parts := strings.SplitN(engine, ":", 2)
	provider := parts[0]
	modelName := ""
	if len(parts) > 1 {
		modelName = parts[1]
	}

	runtime.EventsEmit(ctx, "log", map[string]string{
		"msg": fmt.Sprintf("[ORACLE] Igniting AI Engine: %s / %s", strings.ToUpper(provider), modelName),
		"type": "sys",
	})

	switch provider {
	case "gemini":
		if modelName == "" { modelName = "gemini-2.0-flash" }
		if apiKey == "" {
			return `{"error": "Missing Gemini API Key"}`
		}
		aiResult, err = callGemini(prompt, apiKey, modelName)

	case "deepseek":
		if modelName == "" { modelName = "deepseek-chat" }
		if apiKey == "" {
			return `{"error": "Missing DeepSeek API Key"}`
		}
		aiResult, err = callOpenAICompat(prompt, apiKey, modelName, "https://api.deepseek.com")

	case "qwen":
		// Alibaba Qwen via DashScope OpenAI-compatible endpoint
		if modelName == "" { modelName = "qwen-turbo" }
		if apiKey == "" {
			return `{"error": "Missing Qwen (DashScope) API Key"}`
		}
		aiResult, err = callOpenAICompat(prompt, apiKey, modelName, "https://dashscope.aliyuncs.com/compatible-mode/v1")

	case "minimax":
		// MiniMax OpenAI-compatible endpoint
		if modelName == "" { modelName = "MiniMax-Text-01" }
		if apiKey == "" {
			return `{"error": "Missing MiniMax API Key"}`
		}
		aiResult, err = callOpenAICompat(prompt, apiKey, modelName, "https://api.minimax.chat")

	case "openai":
		if modelName == "" { modelName = "gpt-4o-mini" }
		if apiKey == "" {
			return `{"error": "Missing OpenAI API Key"}`
		}
		aiResult, err = callOpenAICompat(prompt, apiKey, modelName, "https://api.openai.com")

	case "custom":
		if baseURL == "" {
			return `{"error": "Custom endpoint requires a Base URL"}`
		}
		if modelName == "" { modelName = "default" }
		aiResult, err = callOpenAICompat(prompt, apiKey, modelName, baseURL)

	default: // ollama or any unknown
		aiResult, err = callOllama(prompt)
	}

	if err != nil {
		runtime.EventsEmit(ctx, "log", map[string]string{"msg": fmt.Sprintf("[ORACLE ERROR] AI engine failed: %v", err), "type": "err"})
		return fmt.Sprintf(`{"error": "AI engine failed: %v"}`, err)
	}

	// 4. Forge Verifiable Credential
	vcID := "urn:uuid:" + computeSHA256(fmt.Sprintf("%d", time.Now().UnixNano()))
	issuerDID := pubKeyToDIDKey(pubKey)  // W3C did:key format
	nowISO := time.Now().Format(time.RFC3339)

	vc := VCSchema{
		Context: []string{"https://www.w3.org/2018/credentials/v1"},
		ID:      vcID,
		Type:    []string{"VerifiableCredential", "ProofOfWorkCredential"},
		Issuer:  issuerDID,
		IssuanceDate: nowISO,
		CredentialSubject: CredentialSubject{
			ID: issuerDID,
			ProofOfWork: ProofOfWork{
				TimestampRange: []float64{minTs, maxTs},
				FilePaths:      filePaths,
				AIEvaluation:   aiResult,
				HashChainRoot:  latestHash,
			},
		},
	}

	// 5. Sign the Credential — full document signing (P0②)
	//    prevVCHash fetched BEFORE signing so it is covered by the signature (P1③)
	prevVCHash := db.GetLatestVCHash()

	sigPayload := VCSigningPayload{
		Context:           vc.Context,
		ID:                vc.ID,
		Type:              vc.Type,
		Issuer:            vc.Issuer,
		IssuanceDate:      vc.IssuanceDate,
		CredentialSubject: vc.CredentialSubject,
		ProofMeta: VCSigningProofMeta{
			Type:               "Ed25519Signature2020",
			Created:            nowISO,
			VerificationMethod: issuerDID + "#keys-1",
			ProofPurpose:       "assertionMethod",
			PreviousVCHash:     prevVCHash,
		},
	}
	sigPayloadBytes, _ := json.Marshal(sigPayload)
	signature := ed25519.Sign(privKey, sigPayloadBytes)

	vc.Proof = Proof{
		Type:             "Ed25519Signature2020",
		Created:          nowISO,
		VerificationMode: issuerDID + "#keys-1",
		ProofPurpose:     "assertionMethod",
		PreviousVCHash:   prevVCHash,
		ProofValue:       hex.EncodeToString(signature),
	}

	finalJSON, _ := json.MarshalIndent(vc, "", "  ")

	// 6. Save credential to the Ledger database
	// vc_hash = SHA256(vc_id | prevVCHash | full_signed_json)
	vcHash := computeSHA256(vcID + "|" + prevVCHash + "|" + string(finalJSON))

	filePathsStr := strings.Join(filePaths, ",")
	_, dbErr := db.conn.Exec(`
		INSERT OR IGNORE INTO session_credentials
		(vc_id, timestamp, project_context, ai_insight, skill_tags, file_paths, full_vc_json, status, vc_hash, prev_vc_hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
	`,
		vcID,
		float64(time.Now().UnixNano())/1e9,
		workspacePath,
		aiResult,
		"",
		filePathsStr,
		string(finalJSON),
		vcHash,
		prevVCHash,
	)
	if dbErr != nil {
		runtime.EventsEmit(ctx, "log", map[string]string{"msg": fmt.Sprintf("[ORACLE] Warning: Failed to save to ledger: %v", dbErr), "type": "err"})
	} else {
		runtime.EventsEmit(ctx, "log", map[string]string{"msg": fmt.Sprintf("[ORACLE] Credential anchored to chain \u2713 | Block hash: %s...", vcHash[:16]), "type": "sys"})
	}

	// 7. Generate Physical Cyber-Card
	GenerateReport(vc)

	return string(finalJSON)
}

// verifyCredentialDoc cryptographically verifies the Ed25519 signature of a VC JSON string.
// It reconstructs the exact VCSigningPayload that was signed at minting time,
// extracts the public key from the issuer DID, and calls ed25519.Verify.
// Returns (valid bool, errorMessage string).
func verifyCredentialDoc(vcJSON string) (bool, string) {
	var vc VCSchema
	if err := json.Unmarshal([]byte(vcJSON), &vc); err != nil {
		return false, "Invalid VC JSON: " + err.Error()
	}

	if vc.Proof.ProofValue == "" {
		return false, "Credential has no proofValue"
	}
	sigBytes, err := hex.DecodeString(vc.Proof.ProofValue)
	if err != nil {
		return false, "Invalid proofValue hex: " + err.Error()
	}

	// Reconstruct the exact signing payload used at minting time
	payload := VCSigningPayload{
		Context:           vc.Context,
		ID:                vc.ID,
		Type:              vc.Type,
		Issuer:            vc.Issuer,
		IssuanceDate:      vc.IssuanceDate,
		CredentialSubject: vc.CredentialSubject,
		ProofMeta: VCSigningProofMeta{
			Type:               vc.Proof.Type,
			Created:            vc.Proof.Created,
			VerificationMethod: vc.Proof.VerificationMode,
			ProofPurpose:       vc.Proof.ProofPurpose,
			PreviousVCHash:     vc.Proof.PreviousVCHash,
		},
	}
	payloadBytes, _ := json.Marshal(payload)

	// Extract public key from issuer DID (supports both did:key:z... and legacy did:key:ed25519:...)
	pubKey, err := extractPubKeyFromDID(vc.Issuer)
	if err != nil {
		return false, "Cannot extract public key from DID: " + err.Error()
	}
	if len(pubKey) != ed25519.PublicKeySize {
		return false, "Invalid public key length"
	}

	if !ed25519.Verify(pubKey, payloadBytes, sigBytes) {
		return false, "Signature verification failed — credential may have been tampered with"
	}
	return true, ""
}

func getLatestSnapshots(db *VeriHashDB, limit int) ([]Snapshot, error) {
	rows, err := db.conn.Query("SELECT id, timestamp, file_path, content_diff, current_hash, previous_hash FROM file_snapshots ORDER BY id DESC LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var snaps []Snapshot
	for rows.Next() {
		var s Snapshot
		if err := rows.Scan(&s.ID, &s.Timestamp, &s.FilePath, &s.ContentDiff, &s.CurrentHash, &s.PreviousHash); err != nil {
			return nil, err
		}
		snaps = append(snaps, s)
	}
	return snaps, nil
}

func callOllama(prompt string) (string, error) {
	client := resty.New()
	client.SetTimeout(600 * time.Second)

	reqPayload := OllamaRequest{
		Model:  "phi3",
		Prompt: prompt,
		Stream: false,
	}

	var resPayload OllamaResponse

	resp, err := client.R().
		SetHeader("Content-Type", "application/json").
		SetBody(reqPayload).
		SetResult(&resPayload).
		Post("http://127.0.0.1:11434/api/generate")

	if err != nil {
		return "", err
	}
	if resp.IsError() {
		return "", fmt.Errorf("ollama API returned status %d", resp.StatusCode())
	}
	return strings.TrimSpace(resPayload.Response), nil
}

// Gemini specific payloads 
type GeminiRequest struct {
	Contents []GeminiContent `json:"contents"`
}

type GeminiContent struct {
	Parts []GeminiPart `json:"parts"`
}

type GeminiPart struct {
	Text string `json:"text"`
}

func callGemini(prompt, apiKey, modelName string) (string, error) {
	client := resty.New()
	client.SetTimeout(120 * time.Second)
	
	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s", modelName, apiKey)
	
	reqPayload := GeminiRequest{
		Contents: []GeminiContent{
			{
				Parts: []GeminiPart{
					{Text: prompt},
				},
			},
		},
	}
	
	var resPayload map[string]interface{}
	
	resp, err := client.R().
		SetHeader("Content-Type", "application/json").
		SetBody(reqPayload).
		SetResult(&resPayload).
		Post(url)
		
	if err != nil {
		return "", err
	}
	if resp.IsError() {
		return "", fmt.Errorf("gemini API returned status %d: %s", resp.StatusCode(), resp.String())
	}
	
	// Parse nested response from Gemini
	candidates, ok := resPayload["candidates"].([]interface{})
	if ok && len(candidates) > 0 {
		candidate := candidates[0].(map[string]interface{})
		content, ok := candidate["content"].(map[string]interface{})
		if ok {
			parts, ok := content["parts"].([]interface{})
			if ok && len(parts) > 0 {
				part := parts[0].(map[string]interface{})
				text, ok := part["text"].(string)
				if ok {
					return strings.TrimSpace(text), nil
				}
			}
		}
	}
	
	return "", fmt.Errorf("failed to parse gemini response")
}

// callOpenAICompat calls any OpenAI-compatible API (DeepSeek, OpenAI, custom endpoints)
func callOpenAICompat(prompt, apiKey, modelName, baseURL string) (string, error) {
	client := resty.New()
	client.SetTimeout(120 * time.Second)

	url := strings.TrimRight(baseURL, "/") + "/v1/chat/completions"

	reqPayload := map[string]interface{}{
		"model": modelName,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
		"temperature": 0.3,
	}

	var resPayload map[string]interface{}

	resp, err := client.R().
		SetHeader("Content-Type", "application/json").
		SetHeader("Authorization", "Bearer "+apiKey).
		SetBody(reqPayload).
		SetResult(&resPayload).
		Post(url)

	if err != nil {
		return "", err
	}
	if resp.IsError() {
		return "", fmt.Errorf("API returned status %d: %s", resp.StatusCode(), resp.String())
	}

	// Parse OpenAI-format response: choices[0].message.content
	choices, ok := resPayload["choices"].([]interface{})
	if ok && len(choices) > 0 {
		choice := choices[0].(map[string]interface{})
		message, ok := choice["message"].(map[string]interface{})
		if ok {
			content, ok := message["content"].(string)
			if ok {
				return strings.TrimSpace(content), nil
			}
		}
	}

	return "", fmt.Errorf("failed to parse OpenAI-compat response")
}
