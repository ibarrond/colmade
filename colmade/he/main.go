package main

import (
	"fmt"
	"log"
	"math/big"
	"os"
	"unsafe"

	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/ring"
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
var MAX_MASK_VAL = PLAINTEXT_MOD / 3

// -------------------------------------------------------------------------- //

func main() {

	// ···························· GLOBAL SETUP ···························· //
	var err error
	l := log.New(os.Stderr, "", 0)
	prng, err := utils.NewKeyedPRNG([]byte("idemia"))
	if err != nil {
		panic(err)
	}

	// Creating encryption parameters from a default params with logN=13, logQP=218
	//  with a plaintext modulus T=65537
	paramsDef := bfv.PN13QP218
	paramsDef.T = PLAINTEXT_MOD
	params, err := bfv.NewParametersFromLiteral(paramsDef)
	if err != nil {
		panic(err)
	}

	// Create encoder
	encoder := bfv.NewEncoder(params)
	// Create keys
	// -> bfv.NewKeyGenerator(params) for non-debug (non seeded)
	keygen := rlwe.NewTestKeyGenerator(params.Parameters, prng)
	sk := keygen.GenTestSecretKey(prng)
	pk := keygen.GenPublicKey(sk)
	// -> bfv.NewEncryptor(params, pk) for non-debug (non seeded)
	encryptor := bfv.NewTestEncryptor(params, pk, prng)
	maskDecryptor := NewMaskedDecryptor(params, sk, prng, MAX_MASK_VAL)

	// Generate input
	input := make([]uint64, params.N())
	for i := range input {
		input[i] = uint64(i)
	}

	// ·························· ENCRYPTION PHASE ·························· //
	p := bfv.NewPlaintext(params)
	encoder.EncodeUint(input, p)
	ctxt := encryptor.EncryptNew(p)

	// ·························· EVALUATION PHASE ·························· //
	// Nothing for the moment, but to be used for encrypted computation

	// ························MASKED DECRYPTION PHASE ······················ //
	p_decr := maskDecryptor.DecryptMaskedNew(ctxt) // Modified Decryption!
	res := encoder.DecodeUintNew(p_decr)

	// Check result: LSB of all coefficients must be the same as that in input
	l.Printf("\t%v\n", res[:16])
	for i := range res {
		if res[i]%2 != input[i]%2 {
			l.Println("\tincorrect")
			return
		}
	}
	l.Println("\tcorrect")
}

// --------------------------- MASKED DECRYPTION ---------------------------- //

type MaskedDecryptor struct {
	params bfv.Parameters
	sk     *rlwe.SecretKey

	unifSampler *ring.UniformSampler
	gausSampler *ring.GaussianSampler

	maxMaskVal uint64

	indexMatrix   []uint64
	rescaleParams []uint64
	tmpPoly       *ring.Poly
}

func NewMaskedDecryptor(params bfv.Parameters, sk *rlwe.SecretKey, prng *utils.KeyedPRNG, maxMaskVal uint64) *MaskedDecryptor {

	rescaleParams := make([]uint64, len(params.RingQ().Modulus))
	for i, qi := range params.RingQ().Modulus {
		rescaleParams[i] = ring.MForm(ring.ModExp(params.T(), qi-2, qi), qi, params.RingQ().BredParams[i])
	}
	return &MaskedDecryptor{
		params:        params,
		sk:            sk,
		unifSampler:   ring.NewUniformSampler(prng, params.RingT()),
		gausSampler:   ring.NewGaussianSampler(prng, params.RingQ(), params.Sigma(), int(6*params.Sigma())),
		maxMaskVal:    maxMaskVal,
		indexMatrix:   GetIndexMatrixNew(params),
		rescaleParams: rescaleParams,
		tmpPoly:       params.RingT().NewPoly(),
	}
}

// Generate a matrix to spread the coefficients inside a polynomial of degree N
func GetIndexMatrixNew(params bfv.Parameters) (indexMatrix []uint64) {
	var m, pos uint64

	indexMatrix = make([]uint64, params.N())

	logN := uint64(params.LogN())
	rowSize := params.N() >> 1  // 2 rows of size N/2
	m = uint64(params.N()) << 1 // 2*N for the Z_2N ring
	pos = 1

	for i := 0; i < rowSize; i++ {
		indexMatrix[i] = utils.BitReverse64((pos-1)>>1, logN)
		indexMatrix[i|rowSize] = utils.BitReverse64((m-pos-1)>>1, logN)

		pos *= bfv.GaloisGen
		pos &= (m - 1)
	}
	return
}

// Generate an even numbered mask
func (mdcr *MaskedDecryptor) GenMaskArrayNew() (mask_arr []uint64) {
	return mdcr.unifSampler.ReadEvenArrNew(mdcr.maxMaskVal)
}

// Generate an even numbered mask polynomial
func (mdcr *MaskedDecryptor) GenMaskPolyNew() (mask_poly *ring.Poly) {
	mask_poly = mdcr.params.RingQ().NewPoly()

	// Generate seeded []uint64 mask of even values
	mask_arr := mdcr.GenMaskArrayNew()

	// Spread/shuffle coefficients for mask BFV encoding
	for i := 0; i < mdcr.params.N(); i++ {
		mask_poly.Coeffs[0][mdcr.indexMatrix[i]] = mask_arr[i]
	}

	// Final inverse NTT for spread encoding
	mdcr.params.RingT().InvNTT(mask_poly, mask_poly)

	// Apply round((m*Q)/T) mod Q
	mdcr.scaleUp(mask_poly, mask_poly)

	return
}

// takes a poly a mod T and returns round((a*Q)/T) mod Q
func (mdcr *MaskedDecryptor) scaleUp(pIn, pOut *ring.Poly) {
	ringQ := mdcr.params.RingQ()
	ringT := mdcr.params.RingT()
	tmp := mdcr.tmpPoly.Coeffs[0]
	qModTmontgomery := ring.MForm(new(big.Int).Mod(ringQ.ModulusBigint, ringT.ModulusBigint).Uint64(), ringT.Modulus[0], ringT.BredParams[0])

	t := ringT.Modulus[0]
	tHalf := t >> 1
	tInv := ringT.MredParams[0]

	// (x * Q + T/2) mod T
	for i := 0; i < ringQ.N; i = i + 8 {
		x := (*[8]uint64)(unsafe.Pointer(&pIn.Coeffs[0][i]))
		z := (*[8]uint64)(unsafe.Pointer(&tmp[i]))

		z[0] = ring.CRed(ring.MRed(x[0], qModTmontgomery, t, tInv)+tHalf, t)
		z[1] = ring.CRed(ring.MRed(x[1], qModTmontgomery, t, tInv)+tHalf, t)
		z[2] = ring.CRed(ring.MRed(x[2], qModTmontgomery, t, tInv)+tHalf, t)
		z[3] = ring.CRed(ring.MRed(x[3], qModTmontgomery, t, tInv)+tHalf, t)
		z[4] = ring.CRed(ring.MRed(x[4], qModTmontgomery, t, tInv)+tHalf, t)
		z[5] = ring.CRed(ring.MRed(x[5], qModTmontgomery, t, tInv)+tHalf, t)
		z[6] = ring.CRed(ring.MRed(x[6], qModTmontgomery, t, tInv)+tHalf, t)
		z[7] = ring.CRed(ring.MRed(x[7], qModTmontgomery, t, tInv)+tHalf, t)
	}

	// (x * T^-1 - T/2) mod Qi
	for i := 0; i < len(pOut.Coeffs); i++ {
		p0tmp := tmp
		p1tmp := pOut.Coeffs[i]
		qi := ringQ.Modulus[i]
		bredParams := ringQ.BredParams[i]
		mredParams := ringQ.MredParams[i]
		rescaleParams := qi - mdcr.rescaleParams[i]

		tHalfNegQi := qi - ring.BRedAdd(tHalf, qi, bredParams)

		for j := 0; j < ringQ.N; j = j + 8 {

			x := (*[8]uint64)(unsafe.Pointer(&p0tmp[j]))
			z := (*[8]uint64)(unsafe.Pointer(&p1tmp[j]))

			z[0] = ring.MRed(x[0]+tHalfNegQi, rescaleParams, qi, mredParams)
			z[1] = ring.MRed(x[1]+tHalfNegQi, rescaleParams, qi, mredParams)
			z[2] = ring.MRed(x[2]+tHalfNegQi, rescaleParams, qi, mredParams)
			z[3] = ring.MRed(x[3]+tHalfNegQi, rescaleParams, qi, mredParams)
			z[4] = ring.MRed(x[4]+tHalfNegQi, rescaleParams, qi, mredParams)
			z[5] = ring.MRed(x[5]+tHalfNegQi, rescaleParams, qi, mredParams)
			z[6] = ring.MRed(x[6]+tHalfNegQi, rescaleParams, qi, mredParams)
			z[7] = ring.MRed(x[7]+tHalfNegQi, rescaleParams, qi, mredParams)
		}
	}
}

// Decrypt decrypts the ciphertext and write the result in ptOut.
// The level of the output plaintext is min(ciphertext.Level(), plaintext.Level())
// Output domain will match plaintext.Value.IsNTT value.
func (mdcr *MaskedDecryptor) DecryptMaskedNew(ct *bfv.Ciphertext) (ptOut *bfv.Plaintext) {
	pt := bfv.NewPlaintext(mdcr.params)
	temp := mdcr.sk.Value.Q.CopyNew()

	ringQ := mdcr.params.RingQ()

	// Copy c1 to p, and transform to Non-NTT if not done already
	if ct.Value[0].IsNTT {
		ringQ.InvNTT(ct.Value[1], pt.Value)
	} else {
		ring.CopyValues(ct.Value[1], pt.Value)
	}

	// c1 * sk
	ringQ.NTT(pt.Value, pt.Value)
	ringQ.InvMForm(temp, temp)
	ringQ.MulCoeffs(pt.Value, temp, pt.Value)
	ringQ.InvNTT(pt.Value, pt.Value)

	// ---------------------------------------------------------------------
	// Our modification:
	// + ei
	ei := mdcr.gausSampler.ReadNew()
	ringQ.AddNoMod(pt.Value, ei, pt.Value)
	// + mask
	mask := mdcr.GenMaskPolyNew()
	ringQ.AddNoMod(pt.Value, mask, pt.Value)

	// ---------------------------------------------------------------------
	// + c0
	if ct.Value[0].IsNTT {
		ringQ.InvNTTLazy(ct.Value[0], temp)
		ringQ.AddNoMod(pt.Value, temp, pt.Value)
	} else {
		ringQ.AddNoMod(pt.Value, ct.Value[0], pt.Value)
	}

	// mod q
	ringQ.Reduce(pt.Value, pt.Value)

	return pt
}

// ------------------------------- AUXILIARY -------------------------------- //
// Print bfv parameters info
func PrintParams(params bfv.Parameters) {
	ringQ := params.RingQ()
	delta := new(big.Int).Div(ringQ.ModulusBigint, big.NewInt(int64(params.T())))
	fmt.Printf(" --> RingQ: N=%v,\n", (ringQ.N))
	fmt.Printf("   Q=%v,\n", (ringQ.ModulusBigint.String()))
	fmt.Printf("   T=%v,\n", (params.T()))
	fmt.Printf("   Δ=%v,\n", (delta.String()))
}

// Print poly
func PrintPoly(poly *ring.Poly, ring *ring.Ring, name string) []*big.Int {
	arr := make([]*big.Int, ring.N)
	ring.PolyToBigint(poly, arr)
	fmt.Println(" --> ", name, ": [")
	for i := 0; i < 7; i++ {
		fmt.Println("    ", arr[i].String())
	}
	fmt.Println("]")
	return arr
}
