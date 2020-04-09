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

func TestSymmetricDuplication(t *testing.T) {
	k1 := NewSymmetricKey()

	plaintext := "test"
	data := []byte("extra")
	iv := NewIV()
	ciphertext := k1.AuthenticatedEncrypt(plaintext, data, iv)
	k2 := k1.Duplicate()
	decrypted, err := k2.AuthenticatedDecrypt(ciphertext, data, iv)

	if err != nil {
		t.Fatal("Decryption of valid ciphertext with duplicated key produced authentication error")
	}

	if plaintext != decrypted {
		t.Fatal("Decryption with duplicated key  did not return original message")
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
	defer SetFixedRandomness(false)
	k1 := NewSymmetricKey()
	iv := NewIV()

	expected, _ := hex.DecodeString("66687AADF862BD776C8FC18B8E9F8E20089714856EE233B3902A591D0D5F2925")
	if !bytes.Equal(k1.Key, expected) {
		t.Fatal("Key generation failed to match test vector")
	}

	plaintext := "test"
	data := []byte("extra")
	ciphertext := k1.AuthenticatedEncrypt(plaintext, data, iv)
	expected, _ = hex.DecodeString("D1D96BBF2413638BE50654B2CDA85252D8EC47E1")
	if !bytes.Equal(ciphertext, expected) {
		t.Fatal("Encryption failed to produce correct test vector")
	}

	k2 := k1.DeriveKey(0x11)
	expected, _ = hex.DecodeString("1FEFFCD1EC39D618EAAFF762A341B0658C4A08FD7B7BE091CD821F3F57B3EDC0")
	if !bytes.Equal(k2.Key, expected) {
		t.Fatal("Key derivation failed to match test vector")
	}

	k3 := CombineKeys(k1, k2)
	expected, _ = hex.DecodeString("BD4EBCB9AEA251A758ED77FE1E44B32193A741283D351825A2B0A155B85D36E4")
	if !bytes.Equal(k3.Key, expected) {
		t.Fatal("Key derivation failed to match test vector")
	}
}
