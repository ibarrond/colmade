package rlwe

import (
	"github.com/ldsec/lattigo/v2/ring"
	"github.com/ldsec/lattigo/v2/utils"
)

// Encryptor a generic RLWE encryption interface.
type Encryptor interface {
	// Encrypt encrypts the input plaintext and write the result on ctOut.
	// The encryption algorithm depends on the implementor.
	Encrypt(pt *Plaintext, ctOut *Ciphertext)

	// EncryptFromCRP encrypts the input plaintext and writes the result in ctOut.
	// The encryption algorithm depends on the implementor.
	EncryptFromCRP(pt *Plaintext, crp *ring.Poly, ctOut *Ciphertext)
}

// EncryptorBase is a struct used to encrypt Plaintexts. It stores the public-key and/or secret-key.
type EncryptorBase struct {
	Params Parameters

	RingQ *ring.Ring
	RingP *ring.Ring

	PoolQ [1]*ring.Poly
	PoolP [3]*ring.Poly

	GaussianSampler *ring.GaussianSampler
	TernarySampler  *ring.TernarySampler
	UniformSampler  *ring.UniformSampler
}

type PkEncryptor struct {
	EncryptorBase
	Pk            *PublicKey
	Baseconverter *ring.FastBasisExtender
}

type PkFastEncryptor struct {
	EncryptorBase
	Pk *PublicKey
}

type SkEncryptor struct {
	EncryptorBase
	Sk *SecretKey
}

// NewEncryptor instatiates a new generic RLWE Encryptor. The key argument can
// be either a *rlwe.PublicKey or a *rlwe.SecretKey.
func NewEncryptor(params Parameters, key interface{}) Encryptor {
	switch key := key.(type) {
	case *PublicKey:
		if key.Value[0].Q.Degree() != params.N() || key.Value[1].Q.Degree() != params.N() {
			panic("cannot newEncryptor: pk ring degree does not match params ring degree")
		}
		encryptorBase := newEncryptorBase(params)
		if params.PCount() > 0 {
			baseconverter := ring.NewFastBasisExtender(params.ringQ, params.ringP)
			return &PkEncryptor{encryptorBase, key, baseconverter}
		}
		return &PkFastEncryptor{encryptorBase, key}
	case *SecretKey:
		if key.Value.Q.Degree() != params.N() {
			panic("cannot newEncryptor: sk ring degree does not match params ring degree")
		}
		return &SkEncryptor{newEncryptorBase(params), key}
	default:
		panic("key must be either rlwe.PublicKey or rlwe.SecretKey")
	}
}

// NewFastEncryptor instantiates a new  generic RLWE Encryptor.
// This encryptor's Encrypt method first encrypts zero in Q and then adds the plaintext.
// This method is faster than the normal encryptor but result in a noisier ciphertext.
func NewFastEncryptor(params Parameters, key *PublicKey) Encryptor {
	return &PkFastEncryptor{newEncryptorBase(params), key}
}

// Encrypt encrypts the input Plaintext and write the result in ctOut.
func (encryptor *PkEncryptor) Encrypt(plaintext *Plaintext, ctOut *Ciphertext) {
	ringQ := encryptor.RingQ
	ringQP := encryptor.Params.RingQP()

	levelQ := utils.MinInt(plaintext.Level(), ctOut.Level())
	levelP := 0

	poolQ0 := encryptor.PoolQ[0]
	poolP0 := encryptor.PoolP[0]
	poolP1 := encryptor.PoolP[1]
	poolP2 := encryptor.PoolP[2]

	// We sample a R-WLE instance (encryption of zero) over the extended ring (ciphertext ring + special prime)

	ciphertextNTT := ctOut.Value[0].IsNTT

	u := PolyQP{Q: poolQ0, P: poolP2}

	encryptor.TernarySampler.ReadLvl(levelQ, u.Q)
	ringQP.ExtendBasisSmallNormAndCenter(u.Q, levelP, nil, u.P)

	// (#Q + #P) NTT
	ringQP.NTTLvl(levelQ, levelP, u, u)
	ringQP.MFormLvl(levelQ, levelP, u, u)

	ct0QP := PolyQP{Q: ctOut.Value[0], P: poolP0}
	ct1QP := PolyQP{Q: ctOut.Value[1], P: poolP1}

	// ct0 = u*pk0
	// ct1 = u*pk1
	ringQP.MulCoeffsMontgomeryLvl(levelQ, levelP, u, encryptor.Pk.Value[0], ct0QP)
	ringQP.MulCoeffsMontgomeryLvl(levelQ, levelP, u, encryptor.Pk.Value[1], ct1QP)

	// 2*(#Q + #P) NTT
	ringQP.InvNTTLvl(levelQ, levelP, ct0QP, ct0QP)
	ringQP.InvNTTLvl(levelQ, levelP, ct1QP, ct1QP)

	e := PolyQP{Q: poolQ0, P: poolP2}

	encryptor.GaussianSampler.ReadLvl(levelQ, e.Q)
	ringQP.ExtendBasisSmallNormAndCenter(e.Q, levelP, nil, e.P)
	ringQP.AddLvl(levelQ, levelP, ct0QP, e, ct0QP)

	encryptor.GaussianSampler.ReadLvl(levelQ, e.Q)
	ringQP.ExtendBasisSmallNormAndCenter(e.Q, levelP, nil, e.P)
	ringQP.AddLvl(levelQ, levelP, ct1QP, e, ct1QP)

	// ct0 = (u*pk0 + e0)/P
	encryptor.Baseconverter.ModDownQPtoQ(levelQ, levelP, ct0QP.Q, ct0QP.P, ct0QP.Q)

	// ct1 = (u*pk1 + e1)/P
	encryptor.Baseconverter.ModDownQPtoQ(levelQ, levelP, ct1QP.Q, ct1QP.P, ct1QP.Q)

	if ciphertextNTT {

		if !plaintext.Value.IsNTT {
			ringQ.AddLvl(levelQ, ctOut.Value[0], plaintext.Value, ctOut.Value[0])
		}

		// 2*#Q NTT
		ringQ.NTTLvl(levelQ, ctOut.Value[0], ctOut.Value[0])
		ringQ.NTTLvl(levelQ, ctOut.Value[1], ctOut.Value[1])

		if plaintext.Value.IsNTT {
			// ct0 = (u*pk0 + e0)/P + m
			ringQ.AddLvl(levelQ, ctOut.Value[0], plaintext.Value, ctOut.Value[0])
		}

	} else {

		if !plaintext.Value.IsNTT {
			ringQ.AddLvl(levelQ, ctOut.Value[0], plaintext.Value, ctOut.Value[0])
		} else {
			ringQ.InvNTTLvl(levelQ, plaintext.Value, poolQ0)
			ringQ.AddLvl(levelQ, ctOut.Value[0], poolQ0, ctOut.Value[0])
		}
	}

	ctOut.Value[1].IsNTT = ctOut.Value[0].IsNTT
	ctOut.Value[0].Coeffs = ctOut.Value[0].Coeffs[:levelQ+1]
	ctOut.Value[1].Coeffs = ctOut.Value[1].Coeffs[:levelQ+1]
}

// Encrypt encrypts the input Plaintext and write the result in ctOut.
// It first encrypts zero in Q and then adds the plaintext.
// This method is faster than the normal encryptor but result in a noisier ciphertext.
func (encryptor *PkFastEncryptor) Encrypt(plaintext *Plaintext, ctOut *Ciphertext) {
	levelQ := utils.MinInt(plaintext.Level(), ctOut.Level())

	poolQ0 := encryptor.PoolQ[0]

	ringQ := encryptor.RingQ

	ciphertextNTT := ctOut.Value[0].IsNTT

	encryptor.TernarySampler.ReadLvl(levelQ, poolQ0)
	ringQ.NTTLvl(levelQ, poolQ0, poolQ0)
	ringQ.MFormLvl(levelQ, poolQ0, poolQ0)

	// ct0 = u*pk0
	ringQ.MulCoeffsMontgomeryLvl(levelQ, poolQ0, encryptor.Pk.Value[0].Q, ctOut.Value[0])
	// ct1 = u*pk1
	ringQ.MulCoeffsMontgomeryLvl(levelQ, poolQ0, encryptor.Pk.Value[1].Q, ctOut.Value[1])

	if ciphertextNTT {

		// ct1 = u*pk1 + e1
		encryptor.GaussianSampler.ReadLvl(levelQ, poolQ0)
		ringQ.NTTLvl(levelQ, poolQ0, poolQ0)
		ringQ.AddLvl(levelQ, ctOut.Value[1], poolQ0, ctOut.Value[1])

		// ct0 = u*pk0 + e0
		encryptor.GaussianSampler.ReadLvl(levelQ, poolQ0)

		if !plaintext.Value.IsNTT {
			ringQ.AddLvl(levelQ, poolQ0, plaintext.Value, poolQ0)
			ringQ.NTTLvl(levelQ, poolQ0, poolQ0)
			ringQ.AddLvl(levelQ, ctOut.Value[0], poolQ0, ctOut.Value[0])
		} else {
			ringQ.NTTLvl(levelQ, poolQ0, poolQ0)
			ringQ.AddLvl(levelQ, ctOut.Value[0], poolQ0, ctOut.Value[0])
			ringQ.AddLvl(levelQ, ctOut.Value[0], plaintext.Value, ctOut.Value[0])
		}

	} else {

		ringQ.InvNTTLvl(levelQ, ctOut.Value[0], ctOut.Value[0])
		ringQ.InvNTTLvl(levelQ, ctOut.Value[1], ctOut.Value[1])

		// ct[0] = pk[0]*u + e0
		encryptor.GaussianSampler.ReadAndAddLvl(ctOut.Level(), ctOut.Value[0])

		// ct[1] = pk[1]*u + e1
		encryptor.GaussianSampler.ReadAndAddLvl(ctOut.Level(), ctOut.Value[1])

		if !plaintext.Value.IsNTT {
			ringQ.AddLvl(levelQ, ctOut.Value[0], plaintext.Value, ctOut.Value[0])
		} else {
			ringQ.InvNTTLvl(levelQ, plaintext.Value, poolQ0)
			ringQ.AddLvl(levelQ, ctOut.Value[0], poolQ0, ctOut.Value[0])
		}
	}

	ctOut.Value[1].IsNTT = ctOut.Value[0].IsNTT

	ctOut.Value[0].Coeffs = ctOut.Value[0].Coeffs[:levelQ+1]
	ctOut.Value[1].Coeffs = ctOut.Value[1].Coeffs[:levelQ+1]
}

// Encrypt encrypts the input Plaintext and write the result in ctOut.
func (encryptor *SkEncryptor) Encrypt(plaintext *Plaintext, ciphertext *Ciphertext) {
	encryptor.UniformSampler.ReadLvl(utils.MinInt(plaintext.Level(), ciphertext.Level()), ciphertext.Value[1])
	encryptor.encrypt(plaintext, ciphertext)
}

// EncryptFromCRP encrypts the input Plaintext given the uniformly random element c1 and write the result in ctOut.
func (encryptor *SkEncryptor) EncryptFromCRP(plaintext *Plaintext, crp *ring.Poly, ctOut *Ciphertext) {
	ring.CopyValues(crp, ctOut.Value[1])
	encryptor.encrypt(plaintext, ctOut)
}

func (encryptor *SkEncryptor) encrypt(plaintext *Plaintext, ciphertext *Ciphertext) {

	ringQ := encryptor.RingQ

	levelQ := utils.MinInt(plaintext.Level(), ciphertext.Level())

	poolQ0 := encryptor.PoolQ[0]

	ciphertextNTT := ciphertext.Value[0].IsNTT

	ringQ.MulCoeffsMontgomeryLvl(levelQ, ciphertext.Value[1], encryptor.Sk.Value.Q, ciphertext.Value[0])
	ringQ.NegLvl(levelQ, ciphertext.Value[0], ciphertext.Value[0])

	if ciphertextNTT {

		encryptor.GaussianSampler.ReadLvl(levelQ, poolQ0)

		if plaintext.Value.IsNTT {
			ringQ.NTTLvl(levelQ, poolQ0, poolQ0)
			ringQ.AddLvl(levelQ, ciphertext.Value[0], poolQ0, ciphertext.Value[0])
			ringQ.AddLvl(levelQ, ciphertext.Value[0], plaintext.Value, ciphertext.Value[0])
		} else {
			ringQ.AddLvl(levelQ, poolQ0, plaintext.Value, poolQ0)
			ringQ.NTTLvl(levelQ, poolQ0, poolQ0)
			ringQ.AddLvl(levelQ, ciphertext.Value[0], poolQ0, ciphertext.Value[0])
		}

		ciphertext.Value[0].IsNTT = true
		ciphertext.Value[1].IsNTT = true

	} else {

		if plaintext.Value.IsNTT {
			ringQ.AddLvl(levelQ, ciphertext.Value[0], plaintext.Value, ciphertext.Value[0])
			ringQ.InvNTTLvl(levelQ, ciphertext.Value[0], ciphertext.Value[0])

		} else {
			ringQ.InvNTTLvl(levelQ, ciphertext.Value[0], ciphertext.Value[0])
			ringQ.AddLvl(levelQ, ciphertext.Value[0], plaintext.Value, ciphertext.Value[0])
		}

		encryptor.GaussianSampler.ReadAndAddLvl(ciphertext.Level(), ciphertext.Value[0])

		ringQ.InvNTTLvl(levelQ, ciphertext.Value[1], ciphertext.Value[1])

		ciphertext.Value[0].IsNTT = false
		ciphertext.Value[1].IsNTT = false

	}

	ciphertext.Value[0].Coeffs = ciphertext.Value[0].Coeffs[:levelQ+1]
	ciphertext.Value[1].Coeffs = ciphertext.Value[1].Coeffs[:levelQ+1]
}

func newEncryptorBase(params Parameters) EncryptorBase {

	ringQ := params.RingQ()
	ringP := params.RingP()

	prng, err := utils.NewPRNG()
	if err != nil {
		panic(err)
	}

	var poolP [3]*ring.Poly
	if params.PCount() != 0 {
		poolP = [3]*ring.Poly{ringP.NewPoly(), ringP.NewPoly(), ringP.NewPoly()}
	}

	return EncryptorBase{
		Params:          params,
		RingQ:           ringQ,
		RingP:           ringP,
		PoolQ:           [1]*ring.Poly{ringQ.NewPoly()},
		PoolP:           poolP,
		GaussianSampler: ring.NewGaussianSampler(prng, ringQ, params.Sigma(), int(6*params.Sigma())),
		TernarySampler:  ring.NewTernarySampler(prng, ringQ, 0.5, false),
		UniformSampler:  ring.NewUniformSampler(prng, ringQ),
	}
}

func (encryptor *EncryptorBase) EncryptFromCRP(plaintext *Plaintext, crp *ring.Poly, ctOut *Ciphertext) {
	panic("Cannot encrypt with CRP using an encryptor created with the public-key")
}
