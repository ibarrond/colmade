package main

import (
	"fmt"
	"log"
	"math/big"
	"math/bits"
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

type Party struct {
	sk        *rlwe.SecretKey
	ckgShare  *drlwe.CKGShare
	decryptor bfv.Decryptor
	input     []uint64
	res       []uint64
	// from dbfv_test
	e2s         *dbfv.E2SProtocol
	s2e         *dbfv.S2EProtocol
	publicShare *drlwe.CKSShare
	secretShare *rlwe.AdditiveShare
}

var elapsedEncryptParty time.Duration
var elapsedEncryptCloud time.Duration
var elapsedCKGCloud time.Duration
var elapsedCKGParty time.Duration
var elapsedEvalCloud time.Duration
var elapsedEvalParty time.Duration
var elapsedDecrParty time.Duration

func main() {

	// GLOBAL SETUP
	var err error
	l := log.New(os.Stderr, "", 0)

	N := 3 // Default number of parties
	// NGoRoutine := 1 // Default number of Go routines

	// Creating encryption parameters from a default params with logN=13, logQP=218
	//  with a plaintext modulus T=65537
	paramsDef := bfv.PN13QP218
	paramsDef.T = 65537
	params, err := bfv.NewParametersFromLiteral(paramsDef)
	if err != nil {
		panic(err)
	}

	crs, err := utils.NewKeyedPRNG([]byte("idemia"))
	if err != nil {
		panic(err)
	}

	// Create common encoder
	encoder := bfv.NewEncoder(params)
	// Create each party, and allocate the memory for all the shares that the protocols will need
	P := genparties(params, N)
	// Inputs & expected result -> same for all the parties
	expRes := genInputs(params, P)

	// KEYGEN -> Collective public key generation
	pk := ckgphase(params, crs, P)
	l.Printf("\tGlobal Setup done (cloud: %s, party: %s)\n",
		elapsedCKGCloud, elapsedCKGParty)

	// ENCRYPTION PHASE -> Each party encrypts its input vector
	encInputs := encPhase(params, P, pk, encoder)
	///////////////// SEGUIR AQUI!!!! ///////////////////////

	tsk := bfv.NewSecretKey(params)

	params.RingQP().AddLvl(1, 1, P[0].sk.Value, P[1].sk.Value, tsk.Value)
	params.RingQP().AddLvl(1, 1, tsk.Value, P[2].sk.Value, tsk.Value)
	//  + P[1].sk.Value + P[2].sk.Value

	// COLLECTIVE MASKED DECRYPTION PHASE
	res0 := colDecrPhase(encInputs[0], params, P, encoder)

	// check the result
	l.Printf("\t%v\n", res0[:16])
	for i := range expRes {
		if expRes[i] != res0[i]%2 {
			//l.Printf("\t%v\n", expRes)
			l.Println("\tincorrect")
			return
		}
	}
	l.Println("\tcorrect")
	l.Printf("> Finished (total cloud: %s, total party: %s)\n",
		elapsedCKGCloud+elapsedEncryptCloud+elapsedEvalCloud,
		elapsedCKGParty+elapsedEncryptParty+elapsedEvalParty+elapsedDecrParty)

}

func encPhase(params bfv.Parameters, P []*Party, pk *rlwe.PublicKey, encoder bfv.Encoder) (encInputs []*bfv.Ciphertext) {

	l := log.New(os.Stderr, "", 0)

	encInputs = make([]*bfv.Ciphertext, len(P))
	for i := range encInputs {
		encInputs[i] = bfv.NewCiphertext(params, 1)
	}

	// Each party encrypts its input vector
	l.Println("> Encrypt Phase")
	encryptor := bfv.NewEncryptor(params, pk)

	pt := bfv.NewPlaintext(params)
	elapsedEncryptParty = runTimedParty(func() {
		for i, pi := range P {
			encoder.EncodeUint(pi.input, pt)
			encryptor.Encrypt(pt, encInputs[i])
		}
	}, len(P))

	elapsedEncryptCloud = time.Duration(0)
	l.Printf("\tdone (cloud: %s, party: %s)\n", elapsedEncryptCloud, elapsedEncryptParty)

	return
}

func genparties(params bfv.Parameters, N int) []*Party {

	// Create each party, and allocate the memory for all the shares that the protocols will need
	P := make([]*Party, N)
	for i := range P {
		pi := &Party{}
		pi.sk = bfv.NewKeyGenerator(params).GenSecretKey()
		pi.decryptor = bfv.NewDecryptor(params, pi.sk)
		pi.res = make([]uint64, params.N())
		P[i] = pi
		P[i].e2s = dbfv.NewE2SProtocol(params, 3.2)
		P[i].s2e = dbfv.NewS2EProtocol(params, 3.2)
	}

	return P
}

func genInputs(params bfv.Parameters, P []*Party) (expRes []uint64) {
	// Expected result is bit 1 when the input is odd, and bit 0 when it is even
	expRes = make([]uint64, params.N())
	for i := range expRes {
		expRes[i] = uint64(i % 2)
	}

	// Each party generates its input vector (which is the same for all the parties)
	for _, pi := range P {
		pi.input = make([]uint64, params.N())
		for i := range pi.input {
			pi.input[i] = uint64(i)
		}
	}

	return
}

func ckgphase(params bfv.Parameters, crs utils.PRNG, P []*Party) *rlwe.PublicKey {

	l := log.New(os.Stderr, "", 0)

	l.Println("> CKG Phase")

	ckg := dbfv.NewCKGProtocol(params) // Public key generation
	ckgCombined := ckg.AllocateShares()
	for _, pi := range P {
		pi.ckgShare = ckg.AllocateShares()
	}

	crp := ckg.SampleCRP(crs)

	elapsedCKGParty = runTimedParty(func() {
		for _, pi := range P {
			ckg.GenShare(pi.sk, crp, pi.ckgShare)
		}
	}, len(P))

	pk := bfv.NewPublicKey(params)

	elapsedCKGCloud = runTimed(func() {
		for _, pi := range P {
			ckg.AggregateShares(pi.ckgShare, ckgCombined, ckgCombined)
		}
		ckg.GenPublicKey(ckgCombined, crp, pk)
	})

	l.Printf("\tdone (cloud: %s, party: %s)\n", elapsedCKGCloud, elapsedCKGParty)

	return pk
}

func colDecrPhase(ctxt *bfv.Ciphertext, params bfv.Parameters, P []*Party, encoder bfv.Encoder) (results []uint64) {

	l := log.New(os.Stderr, "", 0)

	// Prepare plaintexts
	ptxtOutput := make([]*bfv.Plaintext, len(P))
	for i := range ptxtOutput {
		ptxtOutput[i] = bfv.NewPlaintext(params)
	}

	// Each party encrypts its share
	elapsedDecrParty = runTimedParty(func() {
		for i, pi := range P {
			pi.decryptor.Decrypt(ctxt, ptxtOutput[i])
			encoder.DecodeUint(ptxtOutput[i], pi.res)
		}
	}, len(P))

	// Timing results
	l.Println("> Decrypt Phase")
	l.Printf("\tdone (party: %s)\n", elapsedDecrParty)

	return
}

func GenDecrShare(params bfv.Parameters, sk *rlwe.SecretKey, crp drlwe.CKGCRP, shareOut *drlwe.CKGShare) {

	// Limits for random values
	// max values = floor(sqrt(plaintext modulus))
	// maxvalue := uint64(math.Sqrt(float64(params.T())))

	// maxvalue := uint64(params.T())
	// // binary mask upper-bound for the uniform sampling
	// mask := uint64(1<<bits.Len64(maxvalue) - 1)

	// Result masks
	d := new(big.Int).Div(params.QBigInt(), big.NewInt(int64(params.T())))

	prng, err := utils.NewKeyedPRNG([]byte("idemia"))
	if err != nil {
		panic(err)
	}
	maxvalue := uint64(params.T())
	// binary mask upper-bound for the uniform sampling
	mask := uint64(1<<bits.Len64(maxvalue) - 1)
	ri := ring.RandUniform(prng, maxvalue, mask)
	// r2 := ring.RandUniform(prng, maxvalue, mask)
	// r3 := ring.RandUniform(prng, maxvalue, mask)

	fmt.Println(d, ri)

	// original
	// ringQP := ckg.params.RingQP()

	// ckg.gaussianSamplerQ.Read(shareOut.Value.Q)
	// ringQP.ExtendBasisSmallNormAndCenter(shareOut.Value.Q, ckg.params.PCount()-1, nil, shareOut.Value.P)
	// levelQ, levelP := ckg.params.QCount()-1, ckg.params.PCount()-1
	// ringQP.NTTLvl(levelQ, levelP, shareOut.Value, shareOut.Value)

	// ringQP.MulCoeffsMontgomeryAndSubLvl(levelQ, levelP, sk.Value, rlwe.PolyQP(crp), shareOut.Value)
}

type decryptor struct {
	params bfv.Parameters
	ringQ  *ring.Ring
	pool   *ring.Poly
	sk     *rlwe.SecretKey
}

// Decrypt decrypts the ciphertext and write the result in ptOut.
// The level of the output plaintext is min(ciphertext.Level(), plaintext.Level())
// Output domain will match plaintext.Value.IsNTT value.
func DecryptSb(params rlwe.Parameters, sk *rlwe.SecretKey, ciphertext *bfv.Ciphertext, plaintext *bfv.Plaintext) {

	decryptor := rlwe.NewDecryptor(params, sk)
	ringQ := params.RingQ()

	level := utils.MinInt(ciphertext.Level(), plaintext.Level())

	plaintext.Value.Coeffs = plaintext.Value.Coeffs[:level+1]

	if ciphertext.Value[0].IsNTT {
		ring.CopyValuesLvl(level, ciphertext.Value[ciphertext.Degree()], plaintext.Value)
	} else {
		ringQ.NTTLazyLvl(level, ciphertext.Value[ciphertext.Degree()], plaintext.Value)
	}

	for i := ciphertext.Degree(); i > 0; i-- {

		ringQ.MulCoeffsMontgomeryLvl(level, plaintext.Value, sk.Value.Q, plaintext.Value)

		if !ciphertext.Value[0].IsNTT {
			ringQ.NTTLazyLvl(level, ciphertext.Value[i-1], decryptor.pool)
			ringQ.AddLvl(level, plaintext.Value, decryptor.pool, plaintext.Value)
		} else {
			ringQ.AddLvl(level, plaintext.Value, ciphertext.Value[i-1], plaintext.Value)
		}

		if i&7 == 7 {
			ringQ.ReduceLvl(level, plaintext.Value, plaintext.Value)
		}
	}

	if (ciphertext.Degree())&7 != 7 {
		ringQ.ReduceLvl(level, plaintext.Value, plaintext.Value)
	}

	if !plaintext.Value.IsNTT {
		ringQ.InvNTTLvl(level, plaintext.Value, plaintext.Value)
	}
}
