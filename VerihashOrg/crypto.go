package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
)

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func base58Decode(s string) ([]byte, error) {
	n := big.NewInt(0)
	base := big.NewInt(58)
	for _, c := range s {
		idx := strings.IndexRune(base58Alphabet, c)
		if idx < 0 {
			return nil, fmt.Errorf("invalid base58 character: %c", c)
		}
		n.Mul(n, base)
		n.Add(n, big.NewInt(int64(idx)))
	}
	result := n.Bytes()
	for _, c := range s {
		if c != '1' {
			break
		}
		result = append([]byte{0}, result...)
	}
	return result, nil
}

// extractPubKeyFromDID extracts an Ed25519 public key from a DID string.
func extractPubKeyFromDID(did string) (ed25519.PublicKey, error) {
	if strings.HasPrefix(did, "did:key:z") {
		encoded := strings.TrimPrefix(did, "did:key:z")
		decoded, err := base58Decode(encoded)
		if err != nil {
			return nil, fmt.Errorf("base58 decode failed: %v", err)
		}
		if len(decoded) < 2 || decoded[0] != 0xed || decoded[1] != 0x01 {
			return nil, fmt.Errorf("not an Ed25519 did:key (bad multicodec prefix)")
		}
		if len(decoded) != 34 {
			return nil, fmt.Errorf("invalid ed25519 did:key length")
		}
		return ed25519.PublicKey(decoded[2:]), nil
	}
	if strings.HasPrefix(did, "did:key:ed25519:") {
		pubKeyHex := strings.TrimPrefix(did, "did:key:ed25519:")
		pubKeyBytes, err := hex.DecodeString(pubKeyHex)
		if err != nil {
			return nil, fmt.Errorf("hex decode failed: %v", err)
		}
		if len(pubKeyBytes) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid ed25519 public key length")
		}
		return ed25519.PublicKey(pubKeyBytes), nil
	}
	return nil, fmt.Errorf("unsupported DID format")
}

func buildPublishMessage(did, timestamp, nonce string, payload []byte) []byte {
	hash := sha256.Sum256(payload)
	msg := fmt.Sprintf(
		"VERIHASH-PUBLISH-V1\n%s\n%s\n%s\n%s",
		did,
		timestamp,
		nonce,
		hex.EncodeToString(hash[:]),
	)
	return []byte(msg)
}

func verifyPublishSignature(did, timestamp, nonce string, payload []byte, sigHex string) error {
	pub, err := extractPubKeyFromDID(did)
	if err != nil {
		return err
	}

	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return err
	}

	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature length")
	}

	msg := buildPublishMessage(did, timestamp, nonce, payload)

	if !ed25519.Verify(pub, msg, sig) {
		return fmt.Errorf("invalid request signature")
	}

	return nil
}
