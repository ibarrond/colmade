package main

import (
	"log"
	"math/big"
	"os"

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

func main() {

	// GLOBAL SETUP
	var err error
	l := log.New(os.Stderr, "", 0)
	prng, err := utils.NewKeyedPRNG([]byte("idemia"))
	if err != nil {
		panic(err)
	}

	// Creating encryption parameters from a default params with logN=13, logQP=218
	//  with a plaintext modulus T=65537
	paramsDef := bfv.PN13QP218
	paramsDef.T = 65537
	params, err := bfv.NewParametersFromLiteral(paramsDef)
	if err != nil {
		panic(err)
	}

	// Create encoder
	encoder := bfv.NewEncoder(params)
	// Create keys
	keygen := bfv.NewKeyGenerator(params)
	sk := keygen.GenSecretKey()
	pk := keygen.GenPublicKey(sk)
	encryptor := bfv.NewEncryptor(params, pk)
	decryptor := bfv.NewDecryptor(params, sk)

	// Generate input
	input := make([]uint64, params.N())
	for i := range input {
		input[i] = uint64(i)
	}

	// ENCRYPTION PHASE
	ptxt := bfv.NewPlaintext(params)
	encoder.EncodeUint(input, ptxt)
	ctxt := EncryptNewCustom(encryptor, ptxt)

	// MASKED DECRYPTION PHASE
	ptxt_decr := DecryptMaskedNew(decryptor, prng, ctxt) // Modified Decryption!
	res := encoder.DecodeUintNew(ptxt_decr)

	// CHECK RESULT
	l.Printf("\t%v\n", res[:16])
	for i := range res {
		if res[i]%2 != input[i]%2 {
			//l.Printf("\t%v\n", expRes)
			l.Println("\tincorrect")
			return
		}
	}
	l.Println("\tcorrect")
}

// Decrypt decrypts the ciphertext and write the result in ptOut.
// The level of the output plaintext is min(ciphertext.Level(), plaintext.Level())
// Output domain will match plaintext.Value.IsNTT value.
func DecryptMaskedNew(decryptor bfv.Decryptor, prng *utils.KeyedPRNG, ct *bfv.Ciphertext) (ptOut *bfv.Plaintext) {
	pt := bfv.NewPlaintext(decryptor.Params())
	decr := decryptor.RlweDecryptor()
	params := decryptor.Params()

	ringQ := params.RingQ()
	// ringT := params.RingT()
	// ringP := params.RingP()
	// ringQP := params.RingQP()
	level := utils.MinInt(ct.Level(), pt.Level())
	pt.Value.Coeffs = pt.Value.Coeffs[:level+1]

	// Copy c1 to p, and transform to NTT if not done already
	if ct.Value[0].IsNTT {
		ring.CopyValuesLvl(level, ct.Value[ct.Degree()], pt.Value)
	} else {
		ringQ.NTTLazyLvl(level, ct.Value[ct.Degree()], pt.Value) //
	}

	for i := ct.Degree(); i > 0; i-- {
		// c1 * sk    <NTT domain>
		ringQ.MulCoeffsMontgomeryLvl(level, pt.Value, decr.SecretKey().Value.Q, pt.Value)

		// ---------------------------------------------------------------------
		// Our modification:
		// + ei

		GaussianSampler := ring.NewGaussianSampler(prng, ringQ, params.Sigma(), int(6*params.Sigma()))
		ei := GaussianSampler.ReadLvlNew(level)
		// levelP := 0
		// ringQP.ExtendBasisSmallNormAndCenter(e.Q, levelP, nil, e.P)
		// // divide by P --> needed?
		// BaseConverter := ring.NewFastBasisExtender(ringQ, ringP)
		// BaseConverter.ModDownQPtoQ(levelQ, levelP, ct1QP.Q, ct1QP.P, ct1QP.Q)

		// + d * 2 * ri
		d := new(big.Int).Div(params.QBigInt(), big.NewInt(int64(params.T())))
		UniformSampler := ring.NewUniformSampler(prng, ringQ)
		ri := UniformSampler.ReadNew()             // sample ri (uniform in R_Q) --> could/should be in R_t, but it doesn't matter
		ringQ.MulScalarBigintLvl(level, ri, d, ri) // ri * d
		ringQ.MulScalarLvl(level, ri, 2, ri)       // ri * d * 2
		ringQ.AddLvl(level, ei, ri, ri)            // ei + ri * d * 2
		ringQ.ReduceLvl(level, ri, ri)             // (mod Q)
		ringQ.NTTLazyLvl(level, ri, ri)

		// c1 * sk + ei + d * 2 * ri (mod Q) <NTT domain>
		ringQ.AddLvl(level, pt.Value, ri, pt.Value)

		// ---------------------------------------------------------------------

		// + c0       <NTT domain>
		if !ct.Value[0].IsNTT {
			ringQ.NTTLazyLvl(level, ct.Value[i-1], decr.Pool())  // c0 -> pool
			ringQ.AddLvl(level, pt.Value, decr.Pool(), pt.Value) // c0 + c1 * sk <NTT>
		} else {
			ringQ.AddLvl(level, pt.Value, ct.Value[i-1], pt.Value)
		}
		// mod q    <NTT> (to keep coeffs not too big inside loop)
		if i&7 == 7 {
			ringQ.ReduceLvl(level, pt.Value, pt.Value)
		}
	}
	// mod q    <NTT> (final reduction)
	if (ct.Degree())&7 != 7 {
		ringQ.ReduceLvl(level, pt.Value, pt.Value)
	}
	// undo NTT
	if !pt.Value.IsNTT {
		ringQ.InvNTTLvl(level, pt.Value, pt.Value)
	}
	return pt
}

// Encrypt encrypts the input Plaintext and write the result in ct.
func EncryptNewCustom(encryptor bfv.Encryptor, plaintext *bfv.Plaintext) *bfv.Ciphertext {
	enc, ok := encryptor.RlweEncryptor().(*rlwe.PkEncryptor)
	if !ok {
		panic("encryptor is not a PkEncryptor")
	}

	ct := bfv.NewCiphertext(encryptor.Params(), 1)

	ringQ := enc.RingQ
	ringQP := encryptor.Params().RingQP()

	levelQ := utils.MinInt(plaintext.Level(), ct.Level())
	levelP := 0

	poolQ0 := enc.PoolQ[0]
	poolP0 := enc.PoolP[0]
	poolP1 := enc.PoolP[1]
	poolP2 := enc.PoolP[2]

	// We sample a R-WLE instance (encryption of zero) over the extended ring (ciphertext ring + special prime)

	// ciphertextNTT := ct.Value[0].IsNTT

	u := rlwe.PolyQP{Q: poolQ0, P: poolP2}

	enc.TernarySampler.ReadLvl(levelQ, u.Q)
	ringQP.ExtendBasisSmallNormAndCenter(u.Q, levelP, nil, u.P)

	// (#Q + #P) NTT
	ringQP.NTTLvl(levelQ, levelP, u, u)
	ringQP.MFormLvl(levelQ, levelP, u, u)

	ct0QP := rlwe.PolyQP{Q: ct.Value[0], P: poolP0}
	ct1QP := rlwe.PolyQP{Q: ct.Value[1], P: poolP1}

	// ct0 = u*pk0
	// ct1 = u*pk1
	ringQP.MulCoeffsMontgomeryLvl(levelQ, levelP, u, enc.Pk.Value[0], ct0QP)
	ringQP.MulCoeffsMontgomeryLvl(levelQ, levelP, u, enc.Pk.Value[1], ct1QP)

	// 2*(#Q + #P) NTT
	ringQP.InvNTTLvl(levelQ, levelP, ct0QP, ct0QP)
	ringQP.InvNTTLvl(levelQ, levelP, ct1QP, ct1QP)

	// ES AQUI EL ERROR SAMPLING!!!! --- > Usar esto en decrypt
	e := rlwe.PolyQP{Q: poolQ0, P: poolP2}

	enc.GaussianSampler.ReadLvl(levelQ, e.Q)
	ringQP.ExtendBasisSmallNormAndCenter(e.Q, levelP, nil, e.P)
	ringQP.AddLvl(levelQ, levelP, ct0QP, e, ct0QP)

	enc.GaussianSampler.ReadLvl(levelQ, e.Q)
	ringQP.ExtendBasisSmallNormAndCenter(e.Q, levelP, nil, e.P)
	ringQP.AddLvl(levelQ, levelP, ct1QP, e, ct1QP)

	// ct0 = (u*pk0 + e0)/P
	enc.Baseconverter.ModDownQPtoQ(levelQ, levelP, ct0QP.Q, ct0QP.P, ct0QP.Q)

	// ct1 = (u*pk1 + e1)/P
	enc.Baseconverter.ModDownQPtoQ(levelQ, levelP, ct1QP.Q, ct1QP.P, ct1QP.Q)

	// Fresh ciphertext is not in NTT
	// ct0 = (u*pk0 + e0)/P + m
	if !plaintext.Value.IsNTT {
		ringQ.AddLvl(levelQ, ct.Value[0], plaintext.Value, ct.Value[0])
	} else {
		ringQ.InvNTTLvl(levelQ, plaintext.Value, poolQ0)
		ringQ.AddLvl(levelQ, ct.Value[0], poolQ0, ct.Value[0])
	}

	ct.Value[1].IsNTT = ct.Value[0].IsNTT
	ct.Value[0].Coeffs = ct.Value[0].Coeffs[:levelQ+1]
	ct.Value[1].Coeffs = ct.Value[1].Coeffs[:levelQ+1]

	return ct
}
