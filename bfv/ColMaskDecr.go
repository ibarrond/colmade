package bfv

import (
	"math/big"
	"unsafe"

	"github.com/ldsec/lattigo/v2/ring"
	"github.com/ldsec/lattigo/v2/rlwe"
	"github.com/ldsec/lattigo/v2/utils"
)

// --------------------------- MASKED DECRYPTION ---------------------------- //

type ColMaskDecr struct {
	params Parameters
	sk     *rlwe.SecretKey

	unifSampler *ring.UniformSampler
	gausSampler *ring.GaussianSampler

	maxMaskVal uint64

	indexMatrix   []uint64
	rescaleParams []uint64
	tmpPoly       *ring.Poly
}

func NewColMaskDecr(params Parameters, sk *rlwe.SecretKey, prng *utils.KeyedPRNG, maxMaskVal uint64) *ColMaskDecr {

	rescaleParams := make([]uint64, len(params.RingQ().Modulus))
	for i, qi := range params.RingQ().Modulus {
		rescaleParams[i] = ring.MForm(ring.ModExp(params.T(), qi-2, qi), qi, params.RingQ().BredParams[i])
	}
	return &ColMaskDecr{
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

// Generate an even numbered mask
func (mdcr *ColMaskDecr) GenMaskArrayNew() (mask_arr []uint64) {
	return mdcr.unifSampler.ReadEvenArrNew(mdcr.maxMaskVal)
}

// Generate an even numbered mask polynomial
func (mdcr *ColMaskDecr) GenMaskPolyNew() (mask_poly *ring.Poly) {
	mask_poly = mdcr.params.RingQ().NewPoly()

	// Generate seeded []uint64 mask of even values
	mask_arr := mdcr.GenMaskArrayNew()

	// // To perform cyclic rotations instead of anticyclic
	// //   -> NOT NEEDED! mask elementscan fall on any position
	// for i := 0; i < mdcr.params.N(); i++ {
	// 	mask_poly.Coeffs[0][mdcr.indexMatrix[i]] = mask_arr[i]
	// }
	for i := 0; i < mdcr.params.N(); i++ {
		mask_poly.Coeffs[0][i] = mask_arr[i]
	}

	// Final inverse NTT for coefficient-wise multiplication instead of polynomial
	mdcr.params.RingT().InvNTT(mask_poly, mask_poly)

	// Apply round((m*Q)/T) mod Q
	mdcr.scaleUp(mask_poly, mask_poly)

	return
}

// takes a poly pIn mod T and returns round((pIn*Q)/T) mod Q
func (mdcr *ColMaskDecr) scaleUp(pIn, pOut *ring.Poly) {
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
func (mdcr *ColMaskDecr) DecryptMaskedNew(ct *Ciphertext) (ptOut *Plaintext) {
	pt := NewPlaintext(mdcr.params)

	ringQ := mdcr.params.RingQ()
	temp := ringQ.NewPoly()

	// Copy c1 to p, and transform to InvNTT if not done already
	if ct.Value[1].IsNTT {
		ringQ.InvNTT(ct.Value[1], pt.Value)
	} else {
		ring.CopyValues(ct.Value[1], pt.Value)
	}

	// -------------------------------------------------------------------------
	// Our modification:
	// + mask
	ri := mdcr.GenMaskPolyNew()
	// cri := NewCiphertext(mdcr.params, 1)
	// NewTestEncryptor(mdcr.params, mdcr.sk.Value.Q, mdcr.prng).Encrypt(ri, cri)
	ringQ.AddNoMod(pt.Value, ri, pt.Value)
	// -------------------------------------------------------------------------

	// c1 * sk
	ringQ.MulCoeffsMontgomery(pt.Value, mdcr.sk.Value.Q, pt.Value)
	// ringQ.NTT(pt.Value, pt.Value)
	// ringQ.InvMForm(temp, temp)
	// ringQ.MulCoeffs(pt.Value, temp, pt.Value)
	// ringQ.InvNTT(pt.Value, pt.Value)

	// -------------------------------------------------------------------------
	// Our modification:
	// + ei
	ei := mdcr.gausSampler.ReadNew()
	ringQ.AddNoMod(pt.Value, ei, pt.Value)

	// -------------------------------------------------------------------------
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
