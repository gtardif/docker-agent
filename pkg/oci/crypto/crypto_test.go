package crypto

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	t.Parallel()
	secret := "correct horse battery staple"
	plaintext := []byte("version: \"2\"\nagents:\n  root:\n    model: auto\n")

	payload, err := Encrypt(secret, plaintext)
	require.NoError(t, err)
	require.NotEmpty(t, payload)

	got, err := Decrypt(secret, payload)
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)
}

func TestEncryptIsNonDeterministic(t *testing.T) {
	t.Parallel()
	secret := "s3cret"
	plaintext := []byte("hello world")

	a, err := Encrypt(secret, plaintext)
	require.NoError(t, err)
	b, err := Encrypt(secret, plaintext)
	require.NoError(t, err)

	// Fresh salt + nonce per call, so ciphertext must differ.
	assert.NotEqual(t, a, b)

	// Both still decrypt to the same plaintext.
	da, err := Decrypt(secret, a)
	require.NoError(t, err)
	db, err := Decrypt(secret, b)
	require.NoError(t, err)
	assert.Equal(t, da, db)
}

func TestDecryptWrongKeyFails(t *testing.T) {
	t.Parallel()
	payload, err := Encrypt("right-key", []byte("secret data"))
	require.NoError(t, err)

	_, err = Decrypt("wrong-key", payload)
	assert.ErrorIs(t, err, ErrDecryptionFailed)
}

func TestDecryptTamperedFails(t *testing.T) {
	t.Parallel()
	secret := "key"
	payload, err := Encrypt(secret, []byte("important config"))
	require.NoError(t, err)

	// Decode the envelope, flip a byte of the ciphertext, re-encode.
	raw, err := base64.StdEncoding.DecodeString(payload)
	require.NoError(t, err)
	var env envelope
	require.NoError(t, json.Unmarshal(raw, &env))

	ct, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	require.NoError(t, err)
	require.NotEmpty(t, ct)
	ct[0] ^= 0xFF
	env.Ciphertext = base64.StdEncoding.EncodeToString(ct)

	reraw, err := json.Marshal(env)
	require.NoError(t, err)
	tampered := base64.StdEncoding.EncodeToString(reraw)

	_, err = Decrypt(secret, tampered)
	assert.ErrorIs(t, err, ErrDecryptionFailed)
}

func TestEmptySecret(t *testing.T) {
	t.Parallel()
	_, err := Encrypt("", []byte("x"))
	assert.ErrorIs(t, err, ErrEmptySecret)
	_, err = Decrypt("", "x")
	assert.ErrorIs(t, err, ErrEmptySecret)
}

func TestDecryptInvalidPayload(t *testing.T) {
	t.Parallel()
	_, err := Decrypt("key", "!!!not base64!!!")
	assert.ErrorIs(t, err, ErrInvalidPayload)

	_, err = Decrypt("key", base64.StdEncoding.EncodeToString([]byte("not json")))
	assert.ErrorIs(t, err, ErrInvalidPayload)
}
