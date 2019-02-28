// Test code for symmetric key ops. You should not need to modify this code,
// if any of these tests fail there is likely a problem with your Go
// language installation.
//
// SECURITY WARNING: This code is meant for educational purposes and may
// contain vulnerabilities or other bugs. Please do not use it for
// security-critical applications.
//
// Original version
// Joseph Bonneau February 2019

package chatterbox

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestAESKeyGeneration(t *testing.T) {
	if bytes.Equal(NewSymmetricKey().Key, NewSymmetricKey().Key) {
		t.Fatal("Key generation should produce unique keys")
	}
}

func TestEncryptionDecryption(t *testing.T) {
	k1 := NewSymmetricKey()

	plaintext := "test"
	data := []byte("extra")
	iv := NewIV()
	ciphertext := k1.AuthenticatedEncrypt(plaintext, data, iv)
	decrypted, err := k1.AuthenticatedDecrypt(ciphertext, data, iv)

	if err != nil {
		t.Fatal("Decryption of valid ciphertext produced authentication error")
	}

	iv2 := NewIV()
	if bytes.Equal(ciphertext, k1.AuthenticatedEncrypt(plaintext, data, iv2)) {
		t.Fatal("Encryption under same key, different IV should produce distinct ciphertexts")
	}

	if plaintext != decrypted {
		t.Fatal("Decryption did not return original message")
	}
}

func TestZeroizeSymmetricKey(t *testing.T) {
	k1 := NewSymmetricKey()

	plaintext := "test"
	data := []byte("extra")
	iv := NewIV()
	ciphertext := k1.AuthenticatedEncrypt(plaintext, data, iv)
	k1.Zeroize()

	if _, err := k1.AuthenticatedDecrypt(ciphertext, data, iv); err == nil {
		t.Fatal("Decryption did not fail with zeroized key")
	}

	k2 := NewSymmetricKey()
	k2.Zeroize()
	if !bytes.Equal(k1.Key, k2.Key) {
		t.Fatal("Zeroized keys should be identical")
	}
}

func TestAuthentication(t *testing.T) {
	k1 := NewSymmetricKey()

	plaintext := "test"
	data := []byte("extra")
	iv := NewIV()
	ciphertext := k1.AuthenticatedEncrypt(plaintext, data, iv)

	// flip a bit in ciphertext
	ciphertext[2] ^= 0x1
	if _, err := k1.AuthenticatedDecrypt(ciphertext, data, iv); err == nil {
		t.Fatal("Decryption did not fail on bit flip")
	}
	// undo bit flip in ciphertext
	ciphertext[2] ^= 0x1

	// flip a bit in additional data
	data[2] ^= 0x1
	if _, err := k1.AuthenticatedDecrypt(ciphertext, data, iv); err == nil {
		t.Fatal("Decryption did not fail on additional data alteration")
	}
	// undo bit flip in data
	data[2] ^= 0x1

	// flip a bit in additional data
	iv[2] ^= 0x1
	if _, err := k1.AuthenticatedDecrypt(ciphertext, data, iv); err == nil {
		t.Fatal("Decryption did not fail on IV alteration")
	}
	// undo bit flip in data
	iv[2] ^= 0x1

	if _, err := NewSymmetricKey().AuthenticatedDecrypt(ciphertext, data, iv); err == nil {
		t.Fatal("Decryption did not fail with different key")
	}
}

func TestDerivation(t *testing.T) {
	k1 := NewSymmetricKey()

	k11 := k1.DeriveKey(0x01)

	if bytes.Equal(k1.Key, k11.Key) {
		t.Fatal("Key derivation should lead to different key")
	}

	plaintext := "test"
	data := []byte("extra")
	iv := NewIV()
	ciphertext := k11.AuthenticatedEncrypt(plaintext, data, iv)

	if recovered, err := k11.AuthenticatedDecrypt(ciphertext, data, iv); err != nil || recovered != plaintext {
		t.Fatal("Derived key should be usable")
	}

	if !bytes.Equal(k11.Key, k1.DeriveKey(0x01).Key) {
		t.Fatal("Key derivation should be deterministic")
	}

	if bytes.Equal(k11.Key, k1.DeriveKey(0x02).Key) {
		t.Fatal("Key derivation should be dependent on label")
	}
}

func TestCombination(t *testing.T) {
	k1 := NewSymmetricKey()
	k2 := NewSymmetricKey()

	k12 := CombineKeys(k1, k2)

	plaintext := "test"
	data := []byte("extra")
	iv := NewIV()
	k12.AuthenticatedEncrypt(plaintext, data, iv)

	if bytes.Equal(k1.Key, k12.Key) || bytes.Equal(k2.Key, k12.Key) {
		t.Fatal("Key combination should produce new key")
	}

	if !bytes.Equal(k12.Key, CombineKeys(k1, k2).Key) {
		t.Fatal("Key derivation should be deterministic")
	}
}

// This test vector is specific to AES-GCM and will fail for other algorithms.
func TestVectorAESGCM(t *testing.T) {

	SetFixedRandomness(true)
	k1 := NewSymmetricKey()
	iv := NewIV()
	SetFixedRandomness(false)

	expected, _ := hex.DecodeString("66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925")
	if !bytes.Equal(k1.Key, expected) {
		t.Fatal("Key generation failed to match test vector")
	}

	plaintext := "test"
	data := []byte("extra")
	ciphertext := k1.AuthenticatedEncrypt(plaintext, data, iv)
	expected, _ = hex.DecodeString("8b200dee64be82e8a2e2fb8bb13b924b594e2510")
	if !bytes.Equal(ciphertext, expected) {
		t.Fatal("Encryption failed to produce correct test vector")
	}

	k2 := k1.DeriveKey(0x11)
	expected, _ = hex.DecodeString("1feffcd1ec39d618eaaff762a341b0658c4a08fd7b7be091cd821f3f57b3edc0")
	if !bytes.Equal(k2.Key, expected) {
		t.Fatal("Key derivation failed to match test vector")
	}

	k3 := CombineKeys(k1, k2)
	expected, _ = hex.DecodeString("bd4ebcb9aea251a758ed77fe1e44b32193a741283d351825a2b0a155b85d36e4")
	if !bytes.Equal(k3.Key, expected) {
		t.Fatal("Key derivation failed to match test vector")
	}
}
