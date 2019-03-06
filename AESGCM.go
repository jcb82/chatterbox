// Library code for authenticated encryption/decryption and symmetric key
// management. This code uses AES-GCM for authenticated encryption and a
// SHA-256 based key derivation function.
//
// SECURITY WARNING: This code is meant for educational purposes and may
// contain vulnerabilities or other bugs. Please do not use it for
// security-critical applications.
//
// GRADING NOTES: your code will be evaluated using this code. If you modify
// this code remember that the default version will be used for grading. You
// should add functions as needed in chatter.go or other supplemental files,
// not here.
//
// Original version
// Joseph Bonneau February 2019

package chatterbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
)

const SYMMETRIC_KEY_LENGTH = 32 // 256-bit keys
const IV_LENGTH = 12            // 128-bit nonces
const HASH_OUTPUT_LENGTH = 32   // SHA-256

var fixedRandomReader FixedRandomReader

// Simple PRNG based on SHA256 hashing from a constant intput
type FixedRandom struct {
	state []byte
	index int
}

// Update updates the internal state, when necessary
func (a *FixedRandom) Update() {
	h := sha256.New()
	h.Write(a.state)
	a.state = h.Sum(nil)
}

// Needed to comply with reader interface
type FixedRandomReader struct {
	r *FixedRandom
}

// Read returns random bytes produced by a chain of SHA-256 hashes
func (a FixedRandomReader) Read(p []byte) (int, error) {

	for i := 0; i < len(p); i++ {

		if a.r.index == 0 {
			a.r.Update()
		}

		p[i] = a.r.state[a.r.index]
		a.r.index = (a.r.index + 1) % HASH_OUTPUT_LENGTH
	}
	return len(p), nil
}

// RandomnessSource reveals the real or test randomness source
func RandomnessSource() io.Reader {
	if fixedRandomMode {
		return fixedRandomReader
	} else {
		return rand.Reader
	}
}

// set this flag (at run-time) to use a fixed RNG
var fixedRandomMode = false

func SetFixedRandomness(newValue bool) {
	if newValue == true && fixedRandomMode == false {
		fixedRandomReader = FixedRandomReader{
			r: &FixedRandom{
				state: make([]byte, HASH_OUTPUT_LENGTH),
			},
		}
	}
	fixedRandomMode = newValue
}

// SymmetricKey represents a symmetric key, which is simply a buffer of
// random bytes.
type SymmetricKey struct {
	Key []byte
}

// RandomBytes fills a buffer with the requested number of bytes.
// The data is read from the system PRNG
func RandomBytes(n int) []byte {
	buf := make([]byte, n)
	if _, err := io.ReadFull(RandomnessSource(), buf); err != nil {
		panic(err)
	}
	return buf
}

// NewSymmetricKey creates a new random symmetric key.
// Note: you should not need to call this for your chat application. Every
// key needed will be derived from DH outputs and chains of keys.
func NewSymmetricKey() *SymmetricKey {
	return &SymmetricKey{
		Key: RandomBytes(SYMMETRIC_KEY_LENGTH),
	}
}

// NewSymmetricKey creates a new, random initialization vector
func NewIV() []byte {

	// Use a fixed IV in test mode
	if fixedRandomMode {
		result := make([]byte, IV_LENGTH)
		for i := 0; i < len(result); i++ {
			result[i] = byte(i + 1)
		}
		return result
	}

	return RandomBytes(IV_LENGTH)
}

// String representation of a symmetric key.
func (k *SymmetricKey) String() string {
	return fmt.Sprintf("Symmetric key : % 0X", k.Key)
}

// Duplicate produces an exact copy of a given key
func (k *SymmetricKey) Duplicate() *SymmetricKey {
	r := SymmetricKey{
		Key: make([]byte, SYMMETRIC_KEY_LENGTH),
	}
	copy(r.Key, k.Key)
	return &r
}

// Zeroize overwrites the key bytes with zero bytes
func (k *SymmetricKey) Zeroize() {
	for i := range k.Key {
		k.Key[i] = 0
	}
}

// DeriveKey evalutes a key derivation function (KDF) on a key and returns
// the result. The label modifiers how the KDF operates. Note that the original
// key is left intact and not zeroized.
func (k *SymmetricKey) DeriveKey(label byte) *SymmetricKey {

	h := sha256.New()
	h.Write([]byte{label})
	h.Write(k.Key)
	result := h.Sum(nil)

	return &SymmetricKey{
		Key: result[:SYMMETRIC_KEY_LENGTH],
	}
}

// CombineKeys takes any number of keys as input and combines them into a new
// key. This combined key is a hash of the input keys so does not reveal
// any info about them. This does not zeroize the input keys.
// Note that the order the keys are passed in matters.
func CombineKeys(keys ...*SymmetricKey) *SymmetricKey {

	h := sha256.New()
	for _, k := range keys {
		h.Write(k.Key)
	}

	result := h.Sum(nil)
	return &SymmetricKey{
		Key: result[:SYMMETRIC_KEY_LENGTH],
	}
}

// AuthenticatedEncrypt uses a key k to encrypt a given plaintext and a buffer
// additionalData of data for authentication (but not encryption).
// Since AESGCM is a stream cipher, semantic security requires a new random IV
// for every encryption.
func (k *SymmetricKey) AuthenticatedEncrypt(plaintext string, additionalData, iv []byte) []byte {

	block, err := aes.NewCipher(k.Key)
	if err != nil {
		panic(err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	return aesgcm.Seal(nil, iv, []byte(plaintext), additionalData)
}

// AuthenticatedDecrypt uses a key k to decrypt a given ciphertext and a buffer
// additionalData of data for authentication (but not encryption).
// If the ciphertext or additionalData have been modified, an
// error will be returned.
func (k *SymmetricKey) AuthenticatedDecrypt(ciphertext, additionalData, iv []byte) (string, error) {

	block, err := aes.NewCipher(k.Key)
	if err != nil {
		panic(err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	plaintext, err := aesgcm.Open(nil, iv, ciphertext, additionalData)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
