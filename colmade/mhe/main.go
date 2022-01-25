package main

import (
	"log"
	"math/big"
	"os"
	"time"

	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/dbfv"
	"github.com/ldsec/lattigo/v2/drlwe"
	"github.com/ldsec/lattigo/v2/ring"
	"github.com/ldsec/lattigo/v2/rlwe"
	"github.com/ldsec/lattigo/v2/utils"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func runTimed(f func()) time.Duration {
	start := time.Now()
	f()
	return time.Since(start)
}

func runTimedParty(f func(), N int) time.Duration {
	start := time.Now()
	f()
	return time.Duration(time.Since(start).Nanoseconds() / int64(N))
}

type Bip_s struct {
	pk      *rlwe.PublicKey
	params  bfv.Parameters
	encoder bfv.Encoder
	input   []int64
}

type Gate_s struct {
	pk      *rlwe.PublicKey
	params  bfv.Parameters
	encoder bfv.Encoder
}
type Party_s struct {
	sk        *rlwe.SecretKey
	ckgShare  *drlwe.CKGShare
	decryptor bfv.Decryptor
	input     []int64
}

type PartyPool struct {
	parties   []*Party_s
	params    bfv.Parameters
	encoder   bfv.Encoder
	encryptor bfv.Encryptor
	pk        *rlwe.PublicKey
	prng      *utils.KeyedPRNG
	flagMask  bool
}

func main() {

	// ---------------------------- GLOBAL SETUP ---------------------------- //
	Nparties := 3    // Nnumber of parties
	flagMask := true // Flag to enable/disable masking

	l := log.New(os.Stderr, "", 0)
	pnrg, err := utils.NewKeyedPRNG([]byte("idemia"))
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

	// ---------------------------- INIT PHASE ------------------------------ //
	// Create pool of parties
	PPool := NewPartyPool(params, Nparties, pnrg, flagMask)
	expRes := PPool.GenInputs()
	// Create Biometric Identity Provider and Gate
	Bip := &Bip_s{nil, params, bfv.NewEncoder(params), nil}
	Gate := &Gate_s{nil, params, bfv.NewEncoder(params)}

	// --------------------------- KEYGEN PHASE ----------------------------- //
	// PRIVATE KEY GENERATION --> local
	PPool.SecretKeyGen()
	// PUBLIC KEY GENERATION & DISTRIBUTION
	// Collective public key generation
	pkey := PPool.ColPubKeyGen(pnrg)
	// Distribute public key
	Bip.pk = pkey
	Gate.pk = pkey

	// -------------------------- ENCRYPTION PHASE -------------------------- //
	// ENCRYPTION PHASE -> Encrypt the input vectors
	encInputs := PPool.EncInputs()
	// encRef := Bip.encRef()

	// -------------------------- EVALUATION PHASE -------------------------- //
	// Biometric matching? Other kind of evaluation?

	// -------------------------- DECRYPTION PHASE -------------------------- //
	// COLLECTIVE MASKED DECRYPTION
	pt := ColDecrPhase(encInputs[0], Gate, PPool)

	res := Gate.encoder.DecodeIntNew(pt)

	// check the result
	l.Printf("\t%v\n", res[:16])
	for i := range expRes {
		if expRes[i] != res[i]%2 {
			//l.Printf("\t%v\n", expRes)
			l.Println("\tincorrect")
			return
		}
	}
	l.Println("\tcorrect")

}

// ------------------------------ PARTY POOL -------------------------------- //
// Create common elements, each party, and allocate input vector
func NewPartyPool(params bfv.Parameters, Nparties int, prng *utils.KeyedPRNG, flagMask bool) *PartyPool {
	Pool := &PartyPool{
		make([]*Party_s, Nparties),
		params,
		bfv.NewEncoder(params),
		nil, nil, prng, flagMask}
	for i := range Pool.parties {
		Pool.parties[i] = &Party_s{nil, nil, nil, make([]int64, params.N())}
	}
	return Pool
}

// Generate a private secret key for each party
func (Pool *PartyPool) SecretKeyGen() {
	for _, pi := range Pool.parties {
		pi.sk = bfv.NewKeyGenerator(Pool.params).GenSecretKey()
		pi.decryptor = bfv.NewDecryptor(Pool.params, pi.sk)
	}
}

// Generate inputs and expected result for the pool of parties
func (Pool *PartyPool) GenInputs() (expRes []int64) {
	// Expected result is bit 1 for odd input, 0 for even input
	expRes = make([]int64, Pool.params.N())
	for i := range expRes {
		expRes[i] = int64(i % 2)
	}

	// Each party generates its input vector (which is the same for all the parties)
	for _, pi := range Pool.parties {
		pi.input = make([]int64, Pool.params.N())
		for i := range pi.input {
			pi.input[i] = int64(i)
		}
	}
	return expRes
}

// Collective public key generation
func (Pool *PartyPool) ColPubKeyGen(commonRandomString utils.PRNG) *rlwe.PublicKey {

	ckg := dbfv.NewCKGProtocol(Pool.params)
	ckgCombined := ckg.AllocateShares()
	for _, pi := range Pool.parties {
		pi.ckgShare = ckg.AllocateShares()
	}

	commonRandomPoly := ckg.SampleCRP(commonRandomString)

	for _, pi := range Pool.parties {
		ckg.GenShare(pi.sk, commonRandomPoly, pi.ckgShare)
	}

	for _, pi := range Pool.parties {
		ckg.AggregateShares(pi.ckgShare, ckgCombined, ckgCombined)
	}
	Pool.pk = bfv.NewPublicKey(Pool.params)
	ckg.GenPublicKey(ckgCombined, commonRandomPoly, Pool.pk)
	Pool.encryptor = bfv.NewEncryptor(Pool.params, Pool.pk)
	return Pool.pk
}

// Encrypt the input vectors
func (Pool *PartyPool) EncInputs() (encInputs []*bfv.Ciphertext) {
	// Allocate space for the encrypted input vectors
	encInputs = make([]*bfv.Ciphertext, len(Pool.parties))
	for i := range encInputs {
		encInputs[i] = bfv.NewCiphertext(Pool.params, 1)
	}

	// Each party encrypts its input vector
	ptxt := bfv.NewPlaintext(Pool.params)
	for i, pi := range Pool.parties {
		Pool.encoder.EncodeInt(pi.input, ptxt)
		Pool.encryptor.Encrypt(ptxt, encInputs[i])
	}
	return
}

// Collective Decryption Phase
func ColDecrPhase(ct *bfv.Ciphertext, Gate *Gate_s, Pool *PartyPool) *bfv.Plaintext {

	// The gate extracts c1 and sends it to the parties
	c0, c1 := Gate.ExtractC0C1(ct)

	// Each party 'decrypts' c1 to produce its share
	c1sShares := Pool.ShareDecrypt(c1)

	// The gate aggregates the shares and decrypts the result
	pt := Gate.AggregateAndDecrypt(c1sShares, c0)

	return pt
}

// Generate the decrypted share on each party given c1
func (Pool *PartyPool) ShareDecrypt(c1 *bfv.Plaintext) []*bfv.Plaintext {

	// Prepare result
	c1sShares := make([]*bfv.Plaintext, len(Pool.parties))
	for i := range Pool.parties {
		c1sShares[i] = bfv.NewPlaintext(Pool.params)
	}

	ringQ := Pool.params.RingQ()
	level := c1.Level()
	sigma := Pool.params.Sigma()

	for i, pi := range Pool.parties {

		// c1 * sk    <NTT domain>
		ringQ.MulCoeffsMontgomeryLvl(level, c1.Value, pi.sk.Value.Q, c1sShares[i].Value)

		// + ei
		GaussianSampler := ring.NewGaussianSampler(Pool.prng, ringQ, sigma, int(6*sigma))
		ei := GaussianSampler.ReadLvlNew(level)

		// + d / Nparties * 2 * ri   --> add mask
		if Pool.flagMask {
			d := new(big.Int).Div(Pool.params.QBigInt(),
				big.NewInt(int64(Pool.params.T())))
			// d.Div(d, big.NewInt(int64(len(Pool.parties))*2))

			z := uint64(len(Pool.parties)) * 4
			UniformSampler := ring.NewUniformSampler(Pool.prng, Pool.params.RingQ())

			ri := UniformSampler.ReadNew()             // sample ri (uniform in R_Q)
			ringQ.Mod(ri, Pool.params.T()/z, ri)       // ri quasi uniform in [0, T/z)
			ringQ.MulScalarBigintLvl(level, ri, d, ri) // ri * d
			ringQ.MulScalarLvl(level, ri, 2, ri)       // ri * d * 2
			ringQ.AddLvl(level, ei, ri, ei)            // ei + (ri * d * 2) mod Q
		}

		ringQ.NTTLazyLvl(level, ei, ei)

		// c1 * sk + ei <NTT domain>
		ringQ.AddLvl(level, c1sShares[i].Value, ei, c1sShares[i].Value)
	}
	return c1sShares
}

// --------------------------------- GATE ----------------------------------- //
// Separate ciphertext into two polys c0 and c1
func (Gate *Gate_s) ExtractC0C1(ct *bfv.Ciphertext) (*bfv.Plaintext, *bfv.Plaintext) {
	c0 := bfv.NewPlaintext(Gate.params)
	c1 := bfv.NewPlaintext(Gate.params)
	ringQ := Gate.params.RingQ()
	level := ct.Level()
	if ct.Degree() != 1 {
		panic("ct degree must be set to 1. Please relinearize ct before decrypting")
	}

	c0.Value.Coeffs = c0.Value.Coeffs[:level+1]
	c1.Value.Coeffs = c1.Value.Coeffs[:level+1]
	// Extract and transform to NTT if not done already
	if ct.Value[0].IsNTT {
		ring.CopyValuesLvl(level, ct.Value[0], c0.Value)
		ring.CopyValuesLvl(level, ct.Value[1], c1.Value)
	} else {
		ringQ.NTTLazyLvl(level, ct.Value[0], c0.Value)
		ringQ.NTTLazyLvl(level, ct.Value[1], c1.Value)
	}
	return c0, c1
}

// Aggregate Shares and add c0 to decrypt
func (Gate *Gate_s) AggregateAndDecrypt(c1sShares []*bfv.Plaintext, c0 *bfv.Plaintext) *bfv.Plaintext {
	pt := bfv.NewPlaintext(Gate.params)
	ringQ := Gate.params.RingQ()
	level := c1sShares[0].Level()

	// Aggregate the shares
	for _, c1sShare := range c1sShares {
		ringQ.AddLvl(level, pt.Value, c1sShare.Value, pt.Value) // Σ c1s   <NTT>
	}
	// Add c0
	ringQ.AddLvl(level, pt.Value, c0.Value, pt.Value) // c0 + Σ c1s   <NTT>

	// Mod Q
	ringQ.ReduceLvl(level, pt.Value, pt.Value)

	// Undo NTT
	ringQ.InvNTTLvl(level, pt.Value, pt.Value)

	return pt
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
