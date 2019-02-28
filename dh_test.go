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
	NewKeyPair()
}

func TestKeyRandomness(t *testing.T) {
	kp1 := NewKeyPair()
	kp2 := NewKeyPair()

	if bytes.Equal(kp1.PublicKey.Fingerprint(), kp2.PublicKey.Fingerprint()) {
		t.Errorf("Randomness failure, identical keys generated")
	}
}

func TestDiffieHellman(t *testing.T) {
	kp1 := NewKeyPair()
	kp2 := NewKeyPair()
	kp3 := NewKeyPair()

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

func TestZeroizePrivateKey(t *testing.T) {
	kp1 := NewKeyPair()
	kp2 := NewKeyPair()

	b1 := DHCombine(&kp1.PublicKey, &kp2.PrivateKey)
	kp1.Zeroize()
	b2 := DHCombine(&kp2.PublicKey, &kp1.PrivateKey)

	if bytes.Equal(b1.Key, b2.Key) {
		t.Errorf("Diffie-Hellman succeeded with zeroized key")
	}

	kp1 = NewKeyPair()
	kp2 = NewKeyPair()

	b1 = DHCombine(&kp1.PublicKey, &kp2.PrivateKey)
	kp2.Zeroize()
	b2 = DHCombine(&kp2.PublicKey, &kp1.PrivateKey)

	if !bytes.Equal(b1.Key, b2.Key) {
		t.Errorf("Public key should be usable with zeroized private key")
	}
}

func TestDHVectors(t *testing.T) {

	SetFixedRandomness(true)
	kp1 := NewKeyPair()
	kp2 := NewKeyPair()
	SetFixedRandomness(false)

	expected, _ := hex.DecodeString("662a7aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925")
	if !bytes.Equal(kp1.PrivateKey.Key, expected) {
		t.Fatal("Private key did not match expected test vector")
	}

	expected, _ = hex.DecodeString("7446cb2be09e4967e72b861eb81bc5af")
	if !bytes.Equal(kp1.Fingerprint(), expected) {
		t.Fatal("Fingerprint did not match expected test vector")
	}

	combined := DHCombine(&kp1.PublicKey, &kp2.PrivateKey)
	expected, _ = hex.DecodeString("2c26cd031b4608e7fd36bc9b66c88a8d2ea0305677b74a85f0fa71b97411d459")
	if !bytes.Equal(combined.Key, expected) {
		t.Fatal("DH combination did not match expected test vector")
	}
}
