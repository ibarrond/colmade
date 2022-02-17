package main

import (
	"log"
	"os"

	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/colmade"
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
var MAX_MASK_VAL = PLAINTEXT_MOD - 1

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
	maskDecryptor := colmade.NewMaskDecryptor(params, sk, prng, MAX_MASK_VAL)

	// Generate input
	input := make([]uint64, params.N())
	for i := range input {
		input[i] = uint64(i)
	}

	// ·························· ENCRYPTION PHASE ·························· //
	p := bfv.NewPlaintext(params)
	encoder.EncodeUintNoRot(input, p)
	ctxt := encryptor.EncryptNew(p)

	// ·························· EVALUATION PHASE ·························· //
	// Nothing for the moment, but to be used for encrypted computation.
	//  > Make sure the final ciphertext is fully relinearized! (min degree)

	// ························MASKED DECRYPTION PHASE ······················ //
	p_decr := maskDecryptor.DecryptMaskedNew(ctxt) // Modified Decryption!
	res := make([]uint64, params.N())
	encoder.DecodeUintNoRot(p_decr, res)

	// Check result: LSB of all coefficients must be the same as that in input
	l.Printf("\t%v\n", res[:16])
	correctness := true
	for i := range res {
		if res[i]%2 != input[i]%2 {
			correctness = false
			l.Println("\tincorrect: [", i, "] -> ", res[i])
		}
	}
	l.Printf("\tFINISHED -> ")
	if correctness {
		l.Printf("\tAll OK")
	} else {
		l.Printf("\tErrors Found")
	}

	// ----------------------------- PLAYGROUND ----------------------------- //
	// p_res := bfv.NewPlaintext(params)
	// c0 := ctxt.Value[0].CopyNew()
	// c1 := ctxt.Value[1].CopyNew()
	// s := sk.Value.Q.CopyNew()

	// ringQ := params.RingQ()

	// // c1 * sk
	// c1s := ringQ.NewPoly()
	// ringQ.NTT(c1, c1)
	// ringQ.InvMForm(s, s)
	// ringQ.MulCoeffs(c1, s, c1s)
	// ringQ.InvNTT(c1s, c1s)

	// // ---------------------------------------------------------------------
	// // Our modification:
	// // + mask
	// mask := maskDecryptor.GenMaskPolyNew()
	// ringQ.AddNoMod(c1s, mask, c1s)

	// // ---------------------------------------------------------------------
	// // + c0
	// ringQ.AddNoMod(c1s, c0, c1s)

	// ringQ.NTT(c1s, c1s)

	// check_pol := make([]*big.Int, params.N())
	// for i := range check_pol {
	// 	check_pol[i] = big.NewInt(0)
	// }

	// ringQ.PolyToBigint(c1s, check_pol)
	// cmp_arr := make([]int, params.N())
	// for i := range cmp_arr {
	// 	cmp_arr[i] = check_pol[i].Cmp(ringQ.ModulusBigint)
	// }

	// ringQ.InvNTT(c1s, c1s)
	// // mod q
	// // ringQ.Reduce(pt.Value, pt.Value)
	// p_res.Value = c1s

	// res2 := encoder.DecodeUintNew(p_res)
	// for i := range res2 {
	// 	if res[i]%2 != input[i]%2 {
	// 		correctness = false
	// 		l.Println("\tincorrect: [", i, "] -> ", res[i])
	// 	}
	// }
}
