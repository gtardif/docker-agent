// Package crypto provides authenticated symmetric encryption used to embed a
// full agent YAML into OCI annotations.
//
// The scheme is AES-256-GCM with a key derived from a caller-supplied secret
// (a shared "private key" / passphrase) via scrypt. GCM is an authenticated
// cipher: decryption fails if the ciphertext, nonce, or salt has been modified,
// which gives the required tamper-detection. Anyone holding the same secret can
// recover the original YAML and is guaranteed it has not been altered.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/scrypt"
)

// envelopeVersion identifies the on-the-wire format so the decryptor can reject
// payloads it does not understand and we can evolve the scheme later.
const envelopeVersion = 1

// scrypt parameters. N must be a power of two; these are the widely recommended
// interactive defaults and keep key derivation fast enough for a CLI while
// remaining resistant to brute force.
const (
	scryptN      = 1 << 15 // 32768
	scryptR      = 8
	scryptP      = 1
	keyLen       = 32 // AES-256
	saltLen      = 16
	nonceLenAEAD = 12 // GCM standard nonce size
)

// ErrEmptySecret is returned when an empty encryption/decryption key is given.
var ErrEmptySecret = errors.New("encryption key must not be empty")

// ErrInvalidPayload is returned when a payload cannot be decoded or is malformed.
var ErrInvalidPayload = errors.New("invalid encrypted payload")

// ErrDecryptionFailed is returned when authentication fails: the payload was
// modified or the key is wrong.
var ErrDecryptionFailed = errors.New("decryption failed: wrong key or the data has been tampered with")

// envelope is the JSON structure serialized into the annotation. All binary
// fields are base64 (standard) encoded so the whole thing is a safe string.
type envelope struct {
	Version    int    `json:"v"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ct"`
}

// Encrypt encrypts plaintext with a key derived from secret and returns a
// self-describing, base64-safe string suitable for storing in an OCI
// annotation. A fresh random salt and nonce are generated on every call.
func Encrypt(secret string, plaintext []byte) (string, error) {
	if secret == "" {
		return "", ErrEmptySecret
	}

	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generating salt: %w", err)
	}

	key, err := deriveKey(secret, salt)
	if err != nil {
		return "", err
	}

	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generating nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	env := envelope{
		Version:    envelopeVersion,
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}

	raw, err := json.Marshal(env)
	if err != nil {
		return "", fmt.Errorf("marshaling envelope: %w", err)
	}

	return base64.StdEncoding.EncodeToString(raw), nil
}

// Decrypt reverses Encrypt. It returns ErrDecryptionFailed when the payload has
// been tampered with or the secret is wrong, and ErrInvalidPayload when the
// payload is not a recognized envelope.
func Decrypt(secret, payload string) ([]byte, error) {
	if secret == "" {
		return nil, ErrEmptySecret
	}

	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPayload, err)
	}

	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPayload, err)
	}
	if env.Version != envelopeVersion {
		return nil, fmt.Errorf("%w: unsupported version %d", ErrInvalidPayload, env.Version)
	}

	salt, err := base64.StdEncoding.DecodeString(env.Salt)
	if err != nil {
		return nil, fmt.Errorf("%w: salt: %v", ErrInvalidPayload, err)
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, fmt.Errorf("%w: nonce: %v", ErrInvalidPayload, err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: ciphertext: %v", ErrInvalidPayload, err)
	}

	key, err := deriveKey(secret, salt)
	if err != nil {
		return nil, err
	}

	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}

	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("%w: bad nonce length", ErrInvalidPayload)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		// Authentication failure: wrong key or tampered data.
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

func deriveKey(secret string, salt []byte) ([]byte, error) {
	key, err := scrypt.Key([]byte(secret), salt, scryptN, scryptR, scryptP, keyLen)
	if err != nil {
		return nil, fmt.Errorf("deriving key: %w", err)
	}
	return key, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}
	return gcm, nil
}
