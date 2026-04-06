package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/flosch/pongo2/v6"
)

const reportTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VeriHash PoW Showcase</title>
    <style>
        body {
            background-color: #0d1117;
            color: #e0e0e0;
            font-family: 'Courier New', Courier, monospace;
            padding: 40px;
            display: flex;
            justify-content: center;
        }
        .cyber-card {
            background-color: #161b22;
            border: 2px solid #00ffcc;
            border-radius: 12px;
            padding: 30px;
            box-shadow: 0 0 25px rgba(0, 255, 204, 0.4);
            max-width: 800px;
            width: 100%;
        }
        .header {
            border-bottom: 1px dashed #00ffcc;
            padding-bottom: 15px;
            margin-bottom: 25px;
            display: flex;
            justify-content: space-between;
            align-items: flex-end;
        }
        .title {
            color: #00ffcc;
            font-weight: 900;
            font-size: 1.8rem;
            letter-spacing: 2px;
            text-shadow: 0 0 8px #00ffcc;
        }
        .date {
            font-size: 0.9rem;
            opacity: 0.8;
        }
        .insight {
            background: rgba(0, 255, 204, 0.05);
            padding: 20px;
            border-left: 4px solid #00ffcc;
            font-size: 1.05rem;
            line-height: 1.6;
            white-space: pre-wrap;
            margin-bottom: 25px;
        }
        .badges {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-bottom: 30px;
        }
        .badge {
            background-color: #1f2937;
            border: 1px solid #00ffcc;
            color: #00ffcc;
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: bold;
        }
        .footer {
            border-top: 1px dashed #333;
            padding-top: 20px;
            font-size: 0.75rem;
            color: #777;
            word-break: break-all;
            line-height: 1.5;
        }
        .footer strong {
            color: #999;
        }
    </style>
</head>
<body>
    <div class="cyber-card">
        <div class="header">
            <div class="title">⚡ VERIHASH PoW</div>
            <div class="date">{{ issuanceDate }}</div>
        </div>
        
        <h2 style="color: #fff; margin-top: 0;">{{ projectContext }}</h2>
        
        <div class="insight">{{ insight }}</div>
        
        <div class="badges">
            {% for tag in tags %}
                <span class="badge">{{ tag }}</span>
            {% endfor %}
        </div>
        
        <div class="footer">
            <div><strong>VC ID:</strong> {{ vcID }}</div>
            <div><strong>ISSUER DID:</strong> {{ issuer }}</div>
            <div><strong>SIGNATURE:</strong> {{ signature }}</div>
            <div><strong>ROOT HASH:</strong> {{ hashRoot }}</div>
        </div>
    </div>
</body>
</html>
`

// GenerateReport renders a standalone HTML file from a Minted VC
func GenerateReport(vc VCSchema) error {
	colorYellow := "\033[33m"
	colorGreen := "\033[32m"
	colorReset := "\033[0m"

	fmt.Printf("%s[SYSTEM] Rendering HTML Physical Proof...%s\n", colorYellow, colorReset)

	tpl, err := pongo2.FromString(reportTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse template: %v", err)
	}

	// Extract project context (first file's dir roughly)
	projectContext := "Unknown Workspace"
	if len(vc.CredentialSubject.ProofOfWork.FilePaths) > 0 {
		projectContext = filepath.Dir(vc.CredentialSubject.ProofOfWork.FilePaths[0])
	}

	// Parse insight and tags
	rawEval := vc.CredentialSubject.ProofOfWork.AIEvaluation
	insight := rawEval
	var tags []string

	if strings.Contains(rawEval, "[VERIFIED SKILL TAGS]") {
		parts := strings.Split(rawEval, "[VERIFIED SKILL TAGS]")
		insight = strings.ReplaceAll(strings.TrimSpace(parts[0]), "[WORKLOAD AUDIT]", "")
		insight = strings.TrimSpace(insight)
		
		tagsText := strings.TrimSpace(parts[1])
		rawTags := strings.Split(tagsText, "\n")
		for _, t := range rawTags {
			cleanTag := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(t), "*"))
			if cleanTag != "" {
				tags = append(tags, cleanTag)
			}
		}
	}

	out, err := tpl.Execute(pongo2.Context{
		"issuanceDate":   vc.IssuanceDate,
		"projectContext": projectContext,
		"insight":        insight,
		"tags":           tags,
		"vcID":           vc.ID,
		"issuer":         vc.Issuer,
		"signature":      vc.Proof.ProofValue,
		"hashRoot":       vc.CredentialSubject.ProofOfWork.HashChainRoot,
	})

	if err != nil {
		return fmt.Errorf("failed to execute template: %v", err)
	}

	// Create reports directory if not exists
	reportsDir := "exports"
	os.MkdirAll(reportsDir, 0755)

	fileName := fmt.Sprintf("%s/Proof_of_Work_%s.html", reportsDir, vc.CredentialSubject.ProofOfWork.HashChainRoot[:8])
	
	err = os.WriteFile(fileName, []byte(out), 0644)
	if err != nil {
		return fmt.Errorf("failed to write html file: %v", err)
	}

	fmt.Printf("%s[OK] Physical report materialized at: %s%s\n\n", colorGreen, fileName, colorReset)
	return nil
}
