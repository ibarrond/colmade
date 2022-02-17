package main

import (
	"log"
	"os"

	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/rlwe"
	"github.com/ldsec/lattigo/v2/utils"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

// ------------------------- CONFIGURABLE PARAMS ---------------------------- //
var PLAINTEXT_MOD = uint64(65537)
var MAX_MASK_VAL = PLAINTEXT_MOD / 2

// -------------------------------------------------------------------------- //

func main() {

	// ···························· GLOBAL SETUP ···························· //
	var err error
	l := log.New(os.Stderr, "", 0)
	prng, err := utils.NewKeyedPRNG([]byte("idemia"))
	check(err)

	// Creating encryption parameters from a default params with logN=13, logQP=218
	//  with a plaintext modulus T=65537
	paramsDef := bfv.PN13QP218
	paramsDef.T = PLAINTEXT_MOD
	params, err := bfv.NewParametersFromLiteral(paramsDef)
	check(err)

	// Create encoder
	encoder := bfv.NewEncoder(params)
	// Create keys
	// -> bfv.NewKeyGenerator(params) for non-debug (non seeded)
	keygen := rlwe.NewTestKeyGenerator(params.Parameters, prng)
	sk := keygen.GenTestSecretKey(prng)
	pk := keygen.GenPublicKey(sk)
	// -> bfv.NewEncryptor(params, pk) for non-debug (non seeded)
	encryptor := bfv.NewTestEncryptor(params, pk, prng)
	decryptor := bfv.NewDecryptor(params, sk)
	// maskDecryptor := colmade.NewMaskDecryptor(params, sk, prng, MAX_MASK_VAL)

	// Generate input
	input := make([]uint64, params.N())
	for i := range input {
		input[i] = uint64(i) + 1
	}
	// Generate input
	input2 := make([]uint64, params.N())
	for i := range input2 {
		input2[i] = 0
	}

	// ·························· ENCRYPTION PHASE ·························· //
	p := bfv.NewPlaintext(params)
	p2 := bfv.NewPlaintext(params)
	encoder.EncodeUintBare(input, p)
	encoder.EncodeUintBare(input2, p2)
	ctxt := encryptor.EncryptNew(p)
	ctxt2 := encryptor.EncryptNew(p2)
	ctxts := ctxt.CopyNew()

	// ·························· EVALUATION PHASE ·························· //
	// Nothing for the moment, but to be used for encrypted computation.
	//  > Make sure the final ciphertext is fully relinearized! (min degree)
	ctxts.El().Value[0].Coeffs[0][0] = ctxt2.El().Value[0].Coeffs[0][0]
	ctxts.El().Value[0].Coeffs[1][0] = ctxt2.El().Value[0].Coeffs[1][0]
	ctxts.El().Value[0].Coeffs[2][0] = ctxt2.El().Value[0].Coeffs[2][0]
	ctxts.El().Value[1].Coeffs[0][0] = ctxt2.El().Value[1].Coeffs[0][0]
	ctxts.El().Value[1].Coeffs[1][0] = ctxt2.El().Value[1].Coeffs[1][0]
	ctxts.El().Value[1].Coeffs[2][0] = ctxt2.El().Value[1].Coeffs[2][0]

	// ························MASKED DECRYPTION PHASE ······················ //
	p2_decr := decryptor.DecryptNew(ctxt2) // Original Decryption!
	ps_decr := decryptor.DecryptNew(ctxts) // Modified Decryption!
	res2 := make([]uint64, params.N())
	ress := make([]uint64, params.N())
	encoder.DecodeUintBare(p2_decr, res2)
	encoder.DecodeUintBare(ps_decr, ress)

	// Check result: LSB of all coefficients must be the same as that in input
	l.Printf("SWAPPING")
	l.Printf("\t swapped: %v\n", ress[:10])
	l.Printf("\t orig: %v\n", res2[:10])
	l.Printf("\tFINISHED -> ")

}
