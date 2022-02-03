from BFV import *
from helper import *

from random import randint
from math import log,ceil

# This implementation follows the description at https://eprint.iacr.org/2012/144.pdf
# Brakerski/Fan-Vercauteren (BFV) somewhat homomorphic encryption scheme
#
# Polynomial arithmetic on ciphertext domain is performed in Z[x]_q/x^n+1
# Polynomial arithmetic on plaintext domain is performed in Z[x]_t/x^n+1
# * n: ring size
# * q: ciphertext coefficient modulus
# * t: plaintext coefficient modulus (if t is equal to 2, no negative values is accepted)
# * psi,psiv,w,wv: polynomial arithmetic parameters
#
# Note that n,q,t parameters together determine the multiplicative depth.

# Parameter generation (pre-defined or generate parameters)
PD = 0 # 0: generate -- 1: pre-defined

if PD == 0:
    # Select one of the parameter sets below
    t = 16;   n, q, psi = 1024 , 132120577         , 73993                # log(q) = 27
    # t = 256;  n, q, psi = 2048 , 137438691329      , 22157790             # log(q) = 37
    # t = 1024; n, q, psi = 4096 , 288230376135196673, 60193018759093       # log(q) = 58

    # other necessary parameters
    psiv= modinv(psi,q)
    w   = pow(psi,2,q)
    wv  = modinv(w,q)
else:
    # Enter proper parameters below
    t, n, logq = 16, 1024, 27
    # t, n, logq = 256, 2048, 37
    # t, n, logq = 1024, 4096, 58

    # other necessary parameters (based on n and log(q) determine other parameter)
    q,psi,psiv,w,wv = ParamGen(n,logq) 

# Determine mu, sigma (for discrete gaussian distribution)
mu    = 0
sigma = 0.5 * 3.2

# Determine T, p (for relinearization and galois keys) based on noise analysis 
T = 256
p = q**3 + 1

# Generate polynomial arithmetic tables
w_table    = [1]*n
wv_table   = [1]*n
psi_table  = [1]*n
psiv_table = [1]*n
for i in range(1,n):
    w_table[i]    = ((w_table[i-1]   *w)    % q)
    wv_table[i]   = ((wv_table[i-1]  *wv)   % q)
    psi_table[i]  = ((psi_table[i-1] *psi)  % q)
    psiv_table[i] = ((psiv_table[i-1]*psiv) % q)

qnp = [w_table,wv_table,psi_table,psiv_table]

print("--- Starting BFV Demo")

# Generate BFV evaluator
Evaluator = BFV(n, q, t, mu, sigma, qnp)

# Generate Keys
Evaluator.SecretKeyGen()
Evaluator.PublicKeyGen()
Evaluator.EvalKeyGenV1(T)
Evaluator.EvalKeyGenV2(p)

# print system parameters
print(Evaluator)

# Generate random message
# n1, n2 = 15, -5
n1, n2 = 17543, randint(-(2**15),2**15-1)//2*2

print("--- Random integers n1 and n2 are generated.")
print("* n1: {}".format(n1))
print("* n2: {}".format(n2))
print("* n1+n2: {}".format(n1+n2))
print("* n1-n2: {}".format(n1-n2))
print("* n1*n2: {}".format(n1*n2))
print("")

# Encode random messages into plaintext polynomials
print("--- n1 and n2 are encoded as polynomials m1(x) and m2(x).")
m1 = Evaluator.IntEncode(n1)
m2 = Evaluator.IntEncode(n2)

print("* m1(x): {}".format(m1))
print("* m2(x): {}".format(m2))
print("")

# Encrypt message
ct1 = Evaluator.Encryption(m1)


def MaskedDecryption(self, ct, m2):
    """
    ct <- c1*s + c0
    ct <- floot(ct*(t/q))
    m <- [ct]_t
    """
    # encoded mask is m2
    m = ct[1]*self.sk + ct[0]
    m.F = [((self.t*x)/self.q + y*5) for x, y in zip(m.F, m2.F)]
    m = round(m)
    m = m % self.t
    mr = Poly(self.n,self.t,self.qnp)
    mr.F = m.F
    mr.inNTT = m.inNTT
    return mr

m1_masked = MaskedDecryption(Evaluator, ct1, m2)
print(" OUR MASKING!!! ct_dec    :{}".format(m1_masked))


n1_masked = Evaluator.IntDecode(m1_masked)
print(n1_masked)
