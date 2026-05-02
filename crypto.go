package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/argon2"
)

var (
	identityFile   = DataPath("node_identity.json")
	privateKeyFile = DataPath(".node_secret.key")
)

// NodeIdentity represents the public profile of the user
type NodeIdentity struct {
	PublicKey string `json:"public_key"`
	DID       string `json:"did"`
	CreatedAt string `json:"created_at"`
}

// WalletStatus describes the state of the key file on disk.
type WalletStatus int

const (
	WalletStatusNew        WalletStatus = iota // No key file — first run
	WalletStatusEncrypted                      // Key file is encrypted — needs password
	WalletStatusPlaintext                      // Key file is plaintext — needs migration
)

// initCrypto detects the key file state and returns accordingly.
// - WalletStatusNew: generates a new keypair and mnemonic in memory (NOT saved yet)
// - WalletStatusEncrypted: returns nil keys and WalletStatusEncrypted (caller must unlock)
// - WalletStatusPlaintext: loads the plaintext key and returns WalletStatusPlaintext (caller should migrate)
func initCrypto() (ed25519.PublicKey, ed25519.PrivateKey, WalletStatus, string, error) {
	_, errKey := os.Stat(privateKeyFile)
	if os.IsNotExist(errKey) {
		// First run — generate keys into memory only, don't save yet
		pub, priv, mnemonic, err := generateNewKeyPair()
		if err != nil {
			return nil, nil, WalletStatusNew, "", err
		}
		return pub, priv, WalletStatusNew, mnemonic, nil
	}

	data, err := os.ReadFile(privateKeyFile)
	if err != nil {
		return nil, nil, WalletStatusNew, "", fmt.Errorf("cannot read key file: %v", err)
	}

	if len(data) > 0 && data[0] == '{' {
		// Encrypted bundle format — caller must call loadEncryptedKey(password)
		// Try to load public key from identity file to show DID even when locked
		var pub ed25519.PublicKey
		if idData, err := os.ReadFile(identityFile); err == nil {
			var id NodeIdentity
			if json.Unmarshal(idData, &id) == nil {
				if pkBytes, err := hex.DecodeString(id.PublicKey); err == nil {
					pub = ed25519.PublicKey(pkBytes)
				}
			}
		}
		return pub, nil, WalletStatusEncrypted, "", nil
	}

	// Legacy plaintext hex format — load it and signal migration needed
	pub, priv, err := loadPlaintextKey()
	if err != nil {
		return nil, nil, WalletStatusPlaintext, "", err
	}
	return pub, priv, WalletStatusPlaintext, "", nil
}

func hasExistingKeys() bool {
	_, err1 := os.Stat(identityFile)
	_, err2 := os.Stat(privateKeyFile)
	return err1 == nil && err2 == nil
}

// generateNewKeyPair creates a new BIP39-derived Ed25519 keypair in memory only.
// The caller is responsible for persisting the private key (encrypted or otherwise).
func generateNewKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, string, error) {
	entropy, err := bip39.NewEntropy(128)
	if err != nil {
		return nil, nil, "", fmt.Errorf("entropy generation failed: %v", err)
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return nil, nil, "", fmt.Errorf("mnemonic generation failed: %v", err)
	}
	seed := bip39.NewSeed(mnemonic, "")
	privateKey := ed25519.NewKeyFromSeed(seed[:ed25519.SeedSize])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	printMnemonicWarning(mnemonic)
	return publicKey, privateKey, mnemonic, nil
}

// restoreKeypairFromMnemonic mathematically reconstructs an Ed25519 keypair from a 12-word phrase.
func restoreKeypairFromMnemonic(mnemonic string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, nil, fmt.Errorf("invalid or unrecognized recovery phrase")
	}
	seed := bip39.NewSeed(mnemonic, "")
	privateKey := ed25519.NewKeyFromSeed(seed[:ed25519.SeedSize])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return publicKey, privateKey, nil
}

// generateNewKeys generates a new keypair and saves it as PLAINTEXT (legacy fallback).
// Prefer using generateNewKeyPair + saveEncryptedKeyFile instead.
func generateNewKeys() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	entropy, err := bip39.NewEntropy(128) // 12 words
	if err != nil {
		return nil, nil, fmt.Errorf("entropy generation failed: %v", err)
	}

	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return nil, nil, fmt.Errorf("mnemonic generation failed: %v", err)
	}

	seed := bip39.NewSeed(mnemonic, "")
	privateKey := ed25519.NewKeyFromSeed(seed[:ed25519.SeedSize])
	publicKey := privateKey.Public().(ed25519.PublicKey)

	pubHex := hex.EncodeToString(publicKey)
	did := pubKeyToDIDKey(publicKey)
	identity := NodeIdentity{
		PublicKey: pubHex,
		DID:       did,
		CreatedAt: time.Now().Format(time.RFC3339),
	}

	identityBytes, _ := json.MarshalIndent(identity, "", "  ")
	if err := os.WriteFile(identityFile, identityBytes, 0644); err != nil {
		return nil, nil, err
	}

	privHex := hex.EncodeToString(privateKey)
	if err := os.WriteFile(privateKeyFile, []byte(privHex), 0600); err != nil {
		return nil, nil, err
	}

	printMnemonicWarning(mnemonic)
	return publicKey, privateKey, nil
}

// loadPlaintextKey loads a private key stored in the legacy plaintext hex format.
func loadPlaintextKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return loadKeys()
}

func loadKeys() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	privBytesHex, err := os.ReadFile(privateKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read private key: %v", err)
	}
	privBytes, err := hex.DecodeString(string(privBytesHex))
	if err != nil {
		return nil, nil, fmt.Errorf("invalid private key hex: %v", err)
	}
	if len(privBytes) != ed25519.PrivateKeySize {
		return nil, nil, fmt.Errorf("corrupted private key length")
	}
	privateKey := ed25519.PrivateKey(privBytes)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return publicKey, privateKey, nil
}

// saveEncryptedKeyFile encrypts a private key with the given password and saves it to disk.
// Uses the same AES-256-GCM + Argon2id scheme as the identity bundle export.
func saveEncryptedKeyFile(privKey ed25519.PrivateKey, pubKey ed25519.PublicKey, password string) error {
	did := pubKeyToDIDKey(pubKey)
	// The plaintext is the raw private key bytes (64 bytes)
	encJSON, err := encryptBundleData([]byte(privKey), password, did)
	if err != nil {
		return err
	}
	if err := os.WriteFile(privateKeyFile, encJSON, 0600); err != nil {
		return fmt.Errorf("failed to write encrypted key: %v", err)
	}
	// Also write/update the public identity file
	identity := NodeIdentity{
		PublicKey: hex.EncodeToString(pubKey),
		DID:       did,
		CreatedAt: time.Now().Format(time.RFC3339),
	}
	identityBytes, _ := json.MarshalIndent(identity, "", "  ")
	return os.WriteFile(identityFile, identityBytes, 0644)
}

// loadEncryptedKey decrypts the key file using the given password and returns the keypair.
func loadEncryptedKey(password string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	data, err := os.ReadFile(privateKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot read key file: %v", err)
	}
	plaintext, err := decryptBundleData(data, password)
	if err != nil {
		return nil, nil, err // already has user-friendly message
	}
	if len(plaintext) != ed25519.PrivateKeySize {
		return nil, nil, fmt.Errorf("decrypted data is not a valid Ed25519 private key")
	}
	privKey := ed25519.PrivateKey(plaintext)
	pubKey := privKey.Public().(ed25519.PublicKey)
	return pubKey, privKey, nil
}

func printMnemonicWarning(mnemonic string) {
	colorRed := "\033[31m"
	colorYellow := "\033[33m"
	colorReset := "\033[0m"

	fmt.Printf("\n%s=======================================================%s\n", colorRed, colorReset)
	fmt.Printf("%s CRITICAL: NEW IDENTITY GENERATED %s\n", colorRed, colorReset)
	fmt.Printf("%s=======================================================%s\n", colorRed, colorReset)
	fmt.Printf("Your 12-word recovery phrase is the ONLY way to restore your identity.\n")
	fmt.Printf("Write this down and keep it safe. DO NOT share it.\n\n")
	fmt.Printf("%s%s%s\n\n", colorYellow, mnemonic, colorReset)
	fmt.Printf("%s=======================================================%s\n", colorRed, colorReset)
}

// ── W3C did:key helpers ──────────────────────────────────────────────────────

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func base58Encode(input []byte) string {
	n := new(big.Int).SetBytes(input)
	base := big.NewInt(58)
	zero := big.NewInt(0)
	mod := new(big.Int)
	var result []byte
	for n.Cmp(zero) > 0 {
		n.DivMod(n, base, mod)
		result = append(result, base58Alphabet[mod.Int64()])
	}
	for _, b := range input {
		if b != 0 {
			break
		}
		result = append(result, base58Alphabet[0])
	}
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}
	return string(result)
}

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

// pubKeyToDIDKey encodes an Ed25519 public key as a W3C-compliant did:key.
// Format: did:key:z<multibase-base58btc(0xed01 || pubkey)>
func pubKeyToDIDKey(pubKey ed25519.PublicKey) string {
	prefixed := append([]byte{0xed, 0x01}, pubKey...)
	return "did:key:z" + base58Encode(prefixed)
}

// extractPubKeyFromDID extracts an Ed25519 public key from a DID string.
// Supports both the W3C did:key format (did:key:z...) and the
// legacy hex format used in previous versions (did:key:ed25519:<hex>).
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
		return ed25519.PublicKey(decoded[2:]), nil
	}
	if strings.HasPrefix(did, "did:key:ed25519:") {
		// Legacy hex format — kept for backward compatibility
		pubKeyHex := strings.TrimPrefix(did, "did:key:ed25519:")
		pubKeyBytes, err := hex.DecodeString(pubKeyHex)
		if err != nil {
			return nil, fmt.Errorf("hex decode failed: %v", err)
		}
		return ed25519.PublicKey(pubKeyBytes), nil
	}
	return nil, fmt.Errorf("unsupported DID format")
}

// ─── Bundle Encryption (AES-256-GCM + Argon2id) ─────────────────────────────

// EncryptedBundle is the on-disk format for a password-protected identity bundle.
type EncryptedBundle struct {
	Version    string `json:"version"`    // "v2-encrypted"
	Salt       string `json:"salt"`       // base64(16-byte Argon2id salt)
	Nonce      string `json:"nonce"`      // base64(12-byte AES-GCM nonce)
	Ciphertext string `json:"ciphertext"` // base64(AES-256-GCM ciphertext + auth tag)
	DID        string `json:"did"`        // Public — not secret
	ExportedAt string `json:"exported_at"`
	Note       string `json:"note"`
}

const (
	argon2Time    uint32 = 1
	argon2Memory  uint32 = 64 * 1024 // 64 MB
	argon2Threads uint8  = 4
	argon2KeyLen  uint32 = 32
)

// encryptBundleData encrypts plaintext using AES-256-GCM with an Argon2id-derived key.
func encryptBundleData(plaintext []byte, password, did string) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("salt generation failed: %v", err)
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce generation failed: %v", err)
	}
	key := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)

	bundle := EncryptedBundle{
		Version:    "v2-encrypted",
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
		DID:        did,
		ExportedAt: time.Now().Format(time.RFC3339),
		Note:       "VeriHash Encrypted Identity Bundle — requires backup password to import.",
	}
	return json.MarshalIndent(bundle, "", "  ")
}

// decryptBundleData decrypts an EncryptedBundle back to the original plaintext.
// Returns a user-readable error if the password is wrong or the file is corrupted.
func decryptBundleData(encryptedJSON []byte, password string) ([]byte, error) {
	var bundle EncryptedBundle
	if err := json.Unmarshal(encryptedJSON, &bundle); err != nil {
		return nil, fmt.Errorf("invalid bundle format")
	}
	if bundle.Version != "v2-encrypted" || bundle.Ciphertext == "" {
		return nil, fmt.Errorf("this bundle is not in the encrypted v2 format")
	}
	salt, err := base64.StdEncoding.DecodeString(bundle.Salt)
	if err != nil {
		return nil, fmt.Errorf("corrupted salt field")
	}
	nonce, err := base64.StdEncoding.DecodeString(bundle.Nonce)
	if err != nil {
		return nil, fmt.Errorf("corrupted nonce field")
	}
	ct, err := base64.StdEncoding.DecodeString(bundle.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("corrupted ciphertext field")
	}
	key := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		// AES-GCM auth failure = wrong password or tampered file
		return nil, fmt.Errorf("decryption failed — wrong password or corrupted bundle")
	}
	return plaintext, nil
}
