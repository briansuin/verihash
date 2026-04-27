package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
	LocalMetadata     *LocalMetadata    `json:"localMetadata,omitempty"`
	Proof             Proof             `json:"proof"`
}

type CredentialSubject struct {
	ID          string      `json:"id"`
	ProofOfWork ProofOfWork `json:"proofOfWork"`
}

// FileManifest is the privacy-safe file record stored in the VC.
// Names in the signed manifest are basenames only — full paths are moved to
// the non-signed LocalMetadata block for backup recovery.
type FileManifest struct {
	Name     string `json:"name"`     // basename only, e.g. "contract.pdf"
	SHA256   string `json:"sha256"`   // hex-encoded SHA-256 of the file content
	FileDate string `json:"fileDate"` // OS ModTime (YYYY-MM-DD), physical timestamp watermark
}

// LocalMetadata holds non-signed environment data (like full paths)
// that allow 100% accurate reconstruction of a node's state during restore.
// IMPORTANT: This struct is EXCLUDED from VCSigningPayload.
type LocalMetadata struct {
	FullPaths []string `json:"full_paths,omitempty"`
}

type ProofOfWork struct {
	TimestampRange  []float64      `json:"timestampRange"`
	Files           []FileManifest `json:"files"`
	AIEngine        string         `json:"aiEngine"` // e.g. "GEMINI::gemini-2.5-flash"
	AIEvaluation    string         `json:"aiEvaluation"`
	HashChainRoot   string         `json:"hashChainRoot"`
	ProjectContext  string         `json:"projectContext,omitempty"`
	PublicTitle     string         `json:"publicTitle,omitempty"`
	SkillTags       string         `json:"skillTags,omitempty"`
	UnixNanoMinting string         `json:"unixNanoMinting,omitempty"`
}

type Proof struct {
	Type             string `json:"type"`
	Created          string `json:"created"`
	VerificationMode string `json:"verificationMethod"`
	ProofPurpose     string `json:"proofPurpose"`
	PreviousVCHash   string `json:"previousVCHash,omitempty"`
	ProofValue       string `json:"proofValue"`
}

// VCSigningPayload is the canonical document that is signed.
// It covers all VC fields PLUS proof metadata (excluding proofValue),
// so the signature protects chain linkage and every header field.
type VCSigningPayload struct {
	Context           []string           `json:"@context"`
	ID                string             `json:"id"`
	Type              []string           `json:"type"`
	Issuer            string             `json:"issuer"`
	IssuanceDate      string             `json:"issuanceDate"`
	CredentialSubject CredentialSubject  `json:"credentialSubject"`
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
func MintCredential(ctx context.Context, db *VeriHashDB, pubKey ed25519.PublicKey, privKey ed25519.PrivateKey, engine, apiKey, baseURL string, selectedFilePaths []string, workspacePath string, publicTitle string) string {
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
			if checkLen > 512 {
				checkLen = 512
			}
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
	const maxCharsPerFile = 3000 // ~750 tokens per file
	const maxTotalChars = 60000  // ~15K tokens total hard cap
	var contextBuilder strings.Builder
	seenPaths := map[string]bool{}
	var fullPaths []string          // kept for DB storage only — never goes into VC
	var fileManifest []FileManifest // name+hash — goes into the signed VC
	var minTs, maxTs float64 = snapshots[0].Timestamp, snapshots[0].Timestamp
	latestHash := snapshots[0].CurrentHash
	totalChars := 0

	for _, s := range snapshots {
		if s.Timestamp < minTs {
			minTs = s.Timestamp
		}
		if s.Timestamp > maxTs {
			maxTs = s.Timestamp
		}

		// Uniquify by full path (for DB), build manifest entry per unique file
		if !seenPaths[s.FilePath] {
			seenPaths[s.FilePath] = true
			fullPaths = append(fullPaths, s.FilePath)
			fileManifest = append(fileManifest, buildFileManifest(s.FilePath))
		}

		// Truncate each file's contribution (use basename in AI context, not full path)
		excerpt := s.ContentDiff
		if len(excerpt) > maxCharsPerFile {
			excerpt = excerpt[:maxCharsPerFile] + "\n...[TRUNCATED]"
		}

		// Global cap: stop appending when budget is hit
		if totalChars+len(excerpt) > maxTotalChars {
			contextBuilder.WriteString(fmt.Sprintf("--- File: %s ---\n[BUDGET EXCEEDED — OMITTED]\n\n", filepath.Base(s.FilePath)))
			break
		}

		// Inject physical OS ModTime into AI context for temporal awareness
		fileLabel := filepath.Base(s.FilePath)
		if info, statErr := os.Stat(s.FilePath); statErr == nil {
			fileLabel = fmt.Sprintf("%s (OS Modified: %s)", fileLabel, info.ModTime().Format("2006-01-02"))
		}
		contextBuilder.WriteString(fmt.Sprintf("--- File: %s ---\nContent:\n%s\n\n", fileLabel, excerpt))
		totalChars += len(excerpt)
	}

	runtime.EventsEmit(ctx, "log", map[string]string{"msg": fmt.Sprintf("[ORACLE] Context assembled: ~%d chars / %d files", totalChars, len(fullPaths)), "type": "sys"})

	// 3. Call AI Engine
	prompt := fmt.Sprintf(`You are a professional Work-Certification Auditor and Multi-disciplinary Analyst.
Review the following document manifest and content excerpts to provide a high-precision audit summary of the professional work evidenced.

CRITICAL LANGUAGE RULE:
ALL output (Audit Summary and Skill Tags) MUST be written strictly in ENGLISH, regardless of the source document language.

CRITICAL PRIVACY RULE:
NEVER mention specific proper nouns, real company names, client names, or distinct individual names.
Always use generalized classifications (e.g., "a software service provider", "a commercial entity", "a third-party stakeholder").

Output strictly in this format:
[WORKLOAD AUDIT]
(Provide a 2-paragraph analytical summary in ENGLISH. In your analysis, precisely identify:
1. The INDUSTRY/DOMAIN of the work (e.g., Software Engineering, Creative Design, Corporate Management).
2. The TECHNICAL or PROFESSIONAL SCOPE addressed (e.g., Backend Scaling, UI/UX Refinement, Financial Compliance).
3. The NATURE of the contribution (e.g., Optimization, Strategic Planning, Document Auditing).
4. The TYPES of stakeholders or entities involved (e.g., Enterprise Client, Individual End-user, Institutional Partner).
5. The HISTORICAL TIMELINE or ERA of the work (e.g., explicitly highlight if the documents originate from past decades, demonstrating long-term professional continuity).
Adhere strictly to privacy rules.)

[VERIFIED SKILL TAGS]
* tag1
* tag2

FILE MANIFEST (each file listed with its physical OS modification date as a tamper-evident timestamp):
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
		"msg":  fmt.Sprintf("[ORACLE] Igniting AI Engine: %s / %s", strings.ToUpper(provider), modelName),
		"type": "sys",
	})

	switch provider {
	case "gemini":
		if modelName == "" {
			modelName = "gemini-2.0-flash"
		}
		if apiKey == "" {
			return `{"error": "Missing Gemini API Key"}`
		}
		aiResult, err = callGemini(prompt, apiKey, modelName)

	case "deepseek":
		if modelName == "" {
			modelName = "deepseek-chat"
		}
		if apiKey == "" {
			return `{"error": "Missing DeepSeek API Key"}`
		}
		aiResult, err = callOpenAICompat(prompt, apiKey, modelName, "https://api.deepseek.com")

	case "qwen":
		// Alibaba Qwen via DashScope OpenAI-compatible endpoint
		if modelName == "" {
			modelName = "qwen-turbo"
		}
		if apiKey == "" {
			return `{"error": "Missing Qwen (DashScope) API Key"}`
		}
		aiResult, err = callOpenAICompat(prompt, apiKey, modelName, "https://dashscope.aliyuncs.com/compatible-mode/v1")

	case "minimax":
		// MiniMax OpenAI-compatible endpoint
		if modelName == "" {
			modelName = "MiniMax-Text-01"
		}
		if apiKey == "" {
			return `{"error": "Missing MiniMax API Key"}`
		}
		aiResult, err = callOpenAICompat(prompt, apiKey, modelName, "https://api.minimax.chat")

	case "openai":
		if modelName == "" {
			modelName = "gpt-4o-mini"
		}
		if apiKey == "" {
			return `{"error": "Missing OpenAI API Key"}`
		}
		aiResult, err = callOpenAICompat(prompt, apiKey, modelName, "https://api.openai.com")

	case "claude":
		if modelName == "" {
			modelName = "claude-3-5-sonnet-20241022"
		}
		if apiKey == "" {
			return `{"error": "Missing Anthropic API Key"}`
		}
		aiResult, err = callClaude(prompt, apiKey, modelName)

	case "kimi":
		if modelName == "" {
			modelName = "moonshot-v1-8k"
		}
		if apiKey == "" {
			return `{"error": "Missing Kimi (Moonshot) API Key"}`
		}
		aiResult, err = callOpenAICompat(prompt, apiKey, modelName, "https://api.moonshot.cn")

	case "siliconflow":
		if modelName == "" {
			modelName = "deepseek-ai/DeepSeek-V3"
		}
		if apiKey == "" {
			return `{"error": "Missing SiliconFlow API Key"}`
		}
		aiResult, err = callOpenAICompat(prompt, apiKey, modelName, "https://api.siliconflow.cn")

	case "mistral":
		if modelName == "" {
			modelName = "mistral-large-latest"
		}
		if apiKey == "" {
			return `{"error": "Missing Mistral API Key"}`
		}
		aiResult, err = callOpenAICompat(prompt, apiKey, modelName, "https://api.mistral.ai")

	case "custom":
		if baseURL == "" {
			return `{"error": "Custom endpoint requires a Base URL"}`
		}
		if modelName == "" {
			modelName = "default"
		}
		aiResult, err = callOpenAICompat(prompt, apiKey, modelName, baseURL)

	default: // ollama or any unknown
		aiResult, err = callOllama(prompt)
	}

	if err != nil {
		errMsg := fmt.Sprintf("AI engine failed: %v", err)
		runtime.EventsEmit(ctx, "log", map[string]string{"msg": "[ORACLE ERROR] " + errMsg, "type": "err"})
		errBytes, _ := json.Marshal(map[string]string{"error": errMsg})
		return string(errBytes)
	}

	// Split AI output into clean audit text + structured skill tags.
	// ai_insight stores ONLY the [WORKLOAD AUDIT] prose.
	// skill_tags stores the extracted tags as a separate comma-delimited field.
	parsedTags := parseSkillTagsFromAI(aiResult)
	cleanAIResult := stripSkillTagsFromAI(aiResult)

	// 4. Forge Verifiable Credential
	vcID := "urn:uuid:" + computeSHA256(fmt.Sprintf("%d", time.Now().UnixNano()))
	issuerDID := pubKeyToDIDKey(pubKey) // W3C did:key format
	nowISO := time.Now().Format(time.RFC3339)

	aiEngineUsed := strings.ToUpper(provider)
	if modelName != "" {
		aiEngineUsed += "::" + modelName
	}

	vc := VCSchema{
		Context:      []string{"https://www.w3.org/2018/credentials/v1"},
		ID:           vcID,
		Type:         []string{"VerifiableCredential", "ProofOfWorkCredential"},
		Issuer:       issuerDID,
		IssuanceDate: nowISO,
		CredentialSubject: CredentialSubject{
			ID: issuerDID,
			ProofOfWork: ProofOfWork{
				TimestampRange:  []float64{minTs, maxTs},
				Files:           fileManifest, // name + sha256 only — no full paths
				AIEngine:        aiEngineUsed,
				AIEvaluation:    cleanAIResult,
				HashChainRoot:   latestHash,
				ProjectContext:  workspacePath,
				PublicTitle:     publicTitle,
				SkillTags:       strings.Join(parsedTags, ", "),
				UnixNanoMinting: fmt.Sprintf("%d", time.Now().UnixNano()),
			},
		},
		LocalMetadata: &LocalMetadata{
			FullPaths: fullPaths,
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

	// 6. Save credential to the Ledger database atomically while GCing consumed snapshots
	vcHash := computeSHA256(vcID + "|" + prevVCHash + "|" + string(finalJSON))

	filePathsStr := strings.Join(fullPaths, ",")

	tx, err := db.conn.Begin()
	if err != nil {
		runtime.EventsEmit(ctx, "log", map[string]string{"msg": fmt.Sprintf("[ORACLE ERROR] Transaction start failed: %v", err), "type": "err"})
		return `{"error": "Database transaction failure"}`
	}

	_, dbErr := tx.Exec(`
		INSERT OR IGNORE INTO session_credentials
		(vc_id, timestamp, project_context, ai_insight, skill_tags, file_paths, full_vc_json, status, vc_hash, prev_vc_hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
	`,
		vcID,
		float64(time.Now().UnixNano())/1e9,
		workspacePath,
		cleanAIResult,
		strings.Join(parsedTags, ", "),
		filePathsStr,
		string(finalJSON),
		vcHash,
		prevVCHash,
	)

	if dbErr != nil {
		tx.Rollback()
		runtime.EventsEmit(ctx, "log", map[string]string{"msg": fmt.Sprintf("[ORACLE ERROR] Failed to save to ledger: %v", dbErr), "type": "err"})
		return `{"error": "Database insertion failure"}`
	}

	// Atomic Precision GC: Kill exclusively the fast-fetched consumed Snapshot IDs
	var snapshotIDs []interface{}
	placeholders := ""
	for i, s := range snapshots {
		if i > 0 {
			placeholders += ","
		}
		placeholders += "?"
		snapshotIDs = append(snapshotIDs, s.ID)
	}

	_, gcErr := tx.Exec(fmt.Sprintf(`DELETE FROM file_snapshots WHERE id IN (%s)`, placeholders), snapshotIDs...)
	if gcErr != nil {
		tx.Rollback()
		runtime.EventsEmit(ctx, "log", map[string]string{"msg": fmt.Sprintf("[ORACLE ERROR] GC failed: %v", gcErr), "type": "err"})
		return `{"error": "Garbage collection failure"}`
	}

	commitErr := tx.Commit()
	if commitErr != nil {
		runtime.EventsEmit(ctx, "log", map[string]string{"msg": fmt.Sprintf("[ORACLE ERROR] TX Commit failed: %v", commitErr), "type": "err"})
		return `{"error": "Database commit failure"}`
	}

	runtime.EventsEmit(ctx, "log", map[string]string{"msg": fmt.Sprintf("[ORACLE] Credential anchored \u2713 | Exhaust Cleaned | Block: %s...", vcHash[:16]), "type": "sys"})

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

// buildFileManifest creates a privacy-safe file record containing only the
// file's basename, its SHA-256 content hash, and the OS physical modification
// date (YYYY-MM-DD) as a tamper-evident timestamp watermark.
// Full paths never leave the machine.
func buildFileManifest(fullPath string) FileManifest {
	h := sha256.New()
	f, err := os.Open(fullPath)
	if err == nil {
		_, _ = io.Copy(h, f)
		f.Close()
	}
	// Read the physical OS modification time as a verifiable date anchor
	fileDate := ""
	if info, statErr := os.Stat(fullPath); statErr == nil {
		fileDate = info.ModTime().Format("2006-01-02")
	}
	return FileManifest{
		Name:     filepath.Base(fullPath),
		SHA256:   hex.EncodeToString(h.Sum(nil)),
		FileDate: fileDate,
	}
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

// Anthropic Claude specific payloads
type ClaudeRequest struct {
	Model     string          `json:"model"`
	MaxTokens int             `json:"max_tokens"`
	Messages  []ClaudeMessage `json:"messages"`
}

type ClaudeMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ClaudeResponse struct {
	Content []ClaudeContent `json:"content"`
	Error   *ClaudeError    `json:"error,omitempty"`
}

type ClaudeContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type ClaudeError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

func callClaude(prompt, apiKey, modelName string) (string, error) {
	client := resty.New()
	client.SetTimeout(120 * time.Second)

	url := "https://api.anthropic.com/v1/messages"

	reqPayload := ClaudeRequest{
		Model:     modelName,
		MaxTokens: 1024,
		Messages: []ClaudeMessage{
			{Role: "user", Content: prompt},
		},
	}

	var resPayload ClaudeResponse

	resp, err := client.R().
		SetHeader("Content-Type", "application/json").
		SetHeader("x-api-key", apiKey).
		SetHeader("anthropic-version", "2023-06-01").
		SetBody(reqPayload).
		SetResult(&resPayload).
		Post(url)

	if err != nil {
		return "", err
	}

	if resPayload.Error != nil {
		return "", fmt.Errorf("anthropic API error (%s): %s", resPayload.Error.Type, resPayload.Error.Message)
	}

	if resp.IsError() {
		return "", fmt.Errorf("anthropic API returned status %d: %s", resp.StatusCode(), resp.String())
	}

	if len(resPayload.Content) > 0 {
		return strings.TrimSpace(resPayload.Content[0].Text), nil
	}

	return "", fmt.Errorf("failed to parse Claude response")
}

// parseSkillTagsFromAI extracts individual skill tag strings from the
// [VERIFIED SKILL TAGS] section of the AI output. Lines starting with '*'
// or '-' are treated as tag entries. Returns an empty (non-nil) slice if
// no section is found so JSON marshalling produces [] instead of null.
func parseSkillTagsFromAI(aiText string) []string {
	tags := []string{} // never nil — ensures JSON [] not null
	inSection := false
	for _, line := range strings.Split(aiText, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "[VERIFIED SKILL TAGS]") {
			inSection = true
			continue
		}
		if inSection {
			// Stop at the next section header or blank separator
			if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
				break
			}
			// Strip bullet markers (* or -)
			if strings.HasPrefix(trimmed, "* ") || strings.HasPrefix(trimmed, "- ") {
				tag := strings.TrimSpace(trimmed[2:])
				if tag != "" {
					tags = append(tags, tag)
				}
			}
		}
	}
	return tags
}

// stripSkillTagsFromAI returns only the [WORKLOAD AUDIT] prose from the AI
// output, removing the [VERIFIED SKILL TAGS] section and everything after it.
// This keeps ai_insight clean and prevents duplicate tag data.
func stripSkillTagsFromAI(aiText string) string {
	// Find the start of the skill tags section
	marker := "[VERIFIED SKILL TAGS]"
	if idx := strings.Index(aiText, marker); idx >= 0 {
		return strings.TrimRight(aiText[:idx], " \t\r\n")
	}
	// No tags section found — return as-is (already clean)
	return strings.TrimSpace(aiText)
}
