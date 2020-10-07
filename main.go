package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"

	"github.com/tendermint/ed25519/extra25519"
	"golang.org/x/crypto/curve25519"
)

func main() {
	// generate a new keypair, passing nil as reader uses the crypto/rand.Read
	// function for entropy
	alicePubkey, alicePrivkey, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Alice private key: %s\n", hex.EncodeToString(alicePrivkey))
	fmt.Printf("Alice public key: %s\n", hex.EncodeToString(alicePubkey))

	// generate a new keypair, passing nil as reader uses the crypto/rand.Read
	// function for entropy
	bobPubkey, bobPrivkey, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Bob private key: %s\n", hex.EncodeToString(bobPrivkey))
	fmt.Printf("Bob public key: %s\n", hex.EncodeToString(bobPubkey))

	var aliceSs, bobSs [32]byte

	aliceCurvePriv := PrivateKeyToCurve(alicePrivkey)
	aliceCurvePub := PublicKeyToCurve(alicePubkey)
	bobCurvePriv := PrivateKeyToCurve(bobPrivkey)
	bobCurvePub := PublicKeyToCurve(bobPubkey)

	curve25519.ScalarMult(&aliceSs, &aliceCurvePriv, &bobCurvePub)
	curve25519.ScalarMult(&bobSs, &bobCurvePriv, &aliceCurvePub)

	fmt.Println()
	fmt.Printf("Alice shared secret: %s\n", hex.EncodeToString(aliceSs[:]))
	fmt.Printf("Bob shared secret: %s\n", hex.EncodeToString(bobSs[:]))
}

func PrivateKeyToCurve(privateKey ed25519.PrivateKey) [32]byte {
	var b [64]byte
	copy(b[:], privateKey)

	var out [32]byte
	extra25519.PrivateKeyToCurve25519(&out, &b)

	return out
}

func PublicKeyToCurve(pubkey ed25519.PublicKey) [32]byte {
	var out, b [32]byte
	copy(b[:], pubkey)

	if !extra25519.PublicKeyToCurve25519(&out, &b) {
		panic("pubkey conversion failed")
	}

	return out
}
