// Test code for Diffie-Hellman ops. You should not need to modify this code,
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

func TestKeyGeneration(t *testing.T) {
	GenerateKeyPair()
}

func TestKeyRandomness(t *testing.T) {
	kp1 := GenerateKeyPair()
	kp2 := GenerateKeyPair()

	if bytes.Equal(kp1.PublicKey.Fingerprint(), kp2.PublicKey.Fingerprint()) {
		t.Errorf("Randomness failure, identical keys generated")
	}
}

func TestDiffieHellman(t *testing.T) {
	kp1 := GenerateKeyPair()
	kp2 := GenerateKeyPair()
	kp3 := GenerateKeyPair()

	b1 := DHCombine(&kp1.PublicKey, &kp2.PrivateKey)
	b2 := DHCombine(&kp2.PublicKey, &kp1.PrivateKey)

	if !bytes.Equal(b1.Key, b2.Key) {
		t.Errorf("Diffie-Hellman exchange failure. Both sides should agree")
	}

	b3 := DHCombine(&kp2.PublicKey, &kp3.PrivateKey)

	if bytes.Equal(b1.Key, b3.Key) {
		t.Errorf("Diffie-Hellman failure. Same result with different keys")
	}
}

func TestDHDuplication(t *testing.T) {
	kp1 := GenerateKeyPair()
	kp1c := kp1.Duplicate()

	kp2 := GenerateKeyPair()
	kp2c := kp2.Duplicate()

	b1 := DHCombine(&kp1c.PublicKey, &kp2.PrivateKey)
	b2 := DHCombine(&kp2c.PublicKey, &kp1.PrivateKey)

	if !bytes.Equal(b1.Key, b2.Key) {
		t.Errorf("Diffie-Hellman exchange failure with duplicated key. Both sides should agree")
	}

	b1 = DHCombine(&kp1.PublicKey, &kp2c.PrivateKey)
	b2 = DHCombine(&kp2.PublicKey, &kp1c.PrivateKey)

	if !bytes.Equal(b1.Key, b2.Key) {
		t.Errorf("Diffie-Hellman exchange failure with duplicated key. Both sides should agree")
	}

	b1 = DHCombine(&kp1.PublicKey, kp2c.PrivateKey.Duplicate())
	b2 = DHCombine(&kp2.PublicKey, kp1c.PrivateKey.Duplicate())

	if !bytes.Equal(b1.Key, b2.Key) {
		t.Errorf("Diffie-Hellman exchange failure with duplicated key. Both sides should agree")
	}

	b1 = DHCombine(kp1.PublicKey.Duplicate(), &kp2c.PrivateKey)
	b2 = DHCombine(kp2.PublicKey.Duplicate(), &kp1c.PrivateKey)

	if !bytes.Equal(b1.Key, b2.Key) {
		t.Errorf("Diffie-Hellman exchange failure with duplicated key. Both sides should agree")
	}
}

func TestZeroizePrivateKey(t *testing.T) {
	kp1 := GenerateKeyPair()
	kp2 := GenerateKeyPair()

	b1 := DHCombine(&kp1.PublicKey, &kp2.PrivateKey)
	kp1.Zeroize()
	b2 := DHCombine(&kp2.PublicKey, &kp1.PrivateKey)

	if bytes.Equal(b1.Key, b2.Key) {
		t.Errorf("Diffie-Hellman succeeded with zeroized key")
	}

	kp1 = GenerateKeyPair()
	kp2 = GenerateKeyPair()

	b1 = DHCombine(&kp1.PublicKey, &kp2.PrivateKey)
	kp2.Zeroize()
	b2 = DHCombine(&kp2.PublicKey, &kp1.PrivateKey)

	if !bytes.Equal(b1.Key, b2.Key) {
		t.Errorf("Public key should be usable with zeroized private key")
	}
}

func TestDHVectors(t *testing.T) {

	SetFixedRandomness(true)
	defer SetFixedRandomness(false)
	kp1 := GenerateKeyPair()
	kp2 := GenerateKeyPair()

	expected, _ := hex.DecodeString("662A7AADF862BD776C8FC18B8E9F8E20089714856EE233B3902A591D0D5F2925")
	if !bytes.Equal(kp1.PrivateKey.Key, expected) {
		t.Fatal("Private key did not match expected test vector")
	}

	expected, _ = hex.DecodeString("7446CB2BE09E4967E72B861EB81BC5AF")
	if !bytes.Equal(kp1.Fingerprint(), expected) {
		t.Fatal("Fingerprint did not match expected test vector")
	}

	combined := DHCombine(&kp1.PublicKey, &kp2.PrivateKey)
	expected, _ = hex.DecodeString("2C26CD031B4608E7FD36BC9B66C88A8D2EA0305677B74A85F0FA71B97411D459")
	if !bytes.Equal(combined.Key, expected) {
		t.Fatal("DH combination did not match expected test vector")
	}
}
