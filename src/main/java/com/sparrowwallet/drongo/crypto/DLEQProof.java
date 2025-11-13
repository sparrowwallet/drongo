package com.sparrowwallet.drongo.crypto;

import com.sparrowwallet.drongo.Utils;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.nio.ByteBuffer;

/**
 * Implementation of BIP-374 Discrete Log Equality Proofs.
 *
 * This class provides methods to generate and verify zero-knowledge DLEQ proofs
 * that prove knowledge of a scalar a such that A = a⋅G and C = a⋅B without
 * revealing the value of a.
 */
public class DLEQProof {
    private static final String DLEQ_TAG_AUX = "BIP0374/aux";
    private static final String DLEQ_TAG_NONCE = "BIP0374/nonce";
    private static final String DLEQ_TAG_CHALLENGE = "BIP0374/challenge";

    /**
     * Generate a DLEQ proof according to BIP-374.
     *
     * @param a The secret key (256-bit unsigned integer)
     * @param B The public key point on the curve
     * @param r Auxiliary random data (32 bytes)
     * @param G The generator point (if null, uses secp256k1 generator)
     * @param m Optional message (32 bytes or null)
     * @return The proof (64 bytes) or null if generation fails
     * @throws IllegalArgumentException if r is not 32 bytes or m is not 32 bytes (when provided)
     */
    public static byte[] generateProof(BigInteger a, ECKey B, byte[] r, ECKey G, byte[] m) {
        if(r.length != 32) {
            throw new IllegalArgumentException("Auxiliary random data must be 32 bytes");
        }

        // Fail if a = 0 or a >= n
        if(a.equals(BigInteger.ZERO) || a.compareTo(ECKey.CURVE.getN()) >= 0) {
            return null;
        }

        // Fail if is_infinite(B)
        if(B.getPubKeyPoint().isInfinity()) {
            return null;
        }

        if(m != null && m.length != 32) {
            throw new IllegalArgumentException("Message must be 32 bytes");
        }

        // Use secp256k1 generator if G is null
        if(G == null) {
            G = ECKey.fromPublicOnly(ECKey.CURVE.getG(), true);
        }

        // Let A = a⋅G
        ECKey A = G.multiply(a, true);

        // Let C = a⋅B
        ECKey C = B.multiply(a, true);

        // Let t be the byte-wise xor of bytes(32, a) and hash_BIP0374/aux(r)
        byte[] aBytes = Utils.bigIntegerToBytes(a, 32);
        byte[] auxHash = Utils.taggedHash(DLEQ_TAG_AUX, r);
        byte[] t = Utils.xor(aBytes, auxHash);

        // Let m' = m if m is provided, otherwise an empty byte array
        byte[] mPrime = (m == null) ? new byte[0] : m;

        // Let rand = hash_BIP0374/nonce(t || cbytes(A) || cbytes(C) || m')
        ByteBuffer nonceBuffer = ByteBuffer.allocate(t.length + 33 + 33 + mPrime.length);
        nonceBuffer.put(t);
        nonceBuffer.put(A.getPubKey());
        nonceBuffer.put(C.getPubKey());
        nonceBuffer.put(mPrime);
        byte[] rand = Utils.taggedHash(DLEQ_TAG_NONCE, nonceBuffer.array());

        // Let k = int(rand) mod n
        BigInteger k = new BigInteger(1, rand).mod(ECKey.CURVE.getN());

        // Fail if k = 0
        if(k.equals(BigInteger.ZERO)) {
            return null;
        }

        // Let R1 = k⋅G
        ECKey R1 = G.multiply(k, true);

        // Let R2 = k⋅B
        ECKey R2 = B.multiply(k, true);

        // Let e = int(hash_BIP0374/challenge(...))
        BigInteger e = dleqChallenge(A, B, C, R1, R2, m, G);

        // Let s = (k + e⋅a) mod n
        BigInteger s = k.add(e.multiply(a)).mod(ECKey.CURVE.getN());

        // Let proof = bytes(32, e) || bytes(32, s)
        byte[] proof = new byte[64];
        byte[] eBytes = Utils.bigIntegerToBytes(e, 32);
        byte[] sBytes = Utils.bigIntegerToBytes(s, 32);
        System.arraycopy(eBytes, 0, proof, 0, 32);
        System.arraycopy(sBytes, 0, proof, 32, 32);

        // If VerifyProof fails, abort
        if(!verifyProof(A, B, C, proof, G, m)) {
            return null;
        }

        return proof;
    }

    /**
     * Verify a DLEQ proof according to BIP-374.
     *
     * @param A The public key of the secret key used in proof generation
     * @param B The public key used in proof generation
     * @param C The result of multiplying the secret and public keys (a⋅B)
     * @param proof The proof (64 bytes)
     * @param G The generator point (if null, uses secp256k1 generator)
     * @param m Optional message (32 bytes or null)
     * @return true if the proof is valid, false otherwise
     * @throws IllegalArgumentException if m is not 32 bytes (when provided)
     */
    public static boolean verifyProof(ECKey A, ECKey B, ECKey C, byte[] proof, ECKey G, byte[] m) {
        // Fail if any of is_infinite(A), is_infinite(B), is_infinite(C), is_infinite(G)
        if(A.getPubKeyPoint().isInfinity() || B.getPubKeyPoint().isInfinity() ||
           C.getPubKeyPoint().isInfinity()) {
            return false;
        }

        if(proof.length != 64) {
            return false;
        }

        if(m != null && m.length != 32) {
            throw new IllegalArgumentException("Message must be 32 bytes");
        }

        // Use secp256k1 generator if G is null
        if(G == null) {
            G = ECKey.fromPublicOnly(ECKey.CURVE.getG(), true);
        }

        if(G.getPubKeyPoint().isInfinity()) {
            return false;
        }

        // Let e = int(proof[0:32])
        byte[] eBytes = new byte[32];
        System.arraycopy(proof, 0, eBytes, 0, 32);
        BigInteger e = new BigInteger(1, eBytes);

        // Let s = int(proof[32:64]); fail if s >= n
        byte[] sBytes = new byte[32];
        System.arraycopy(proof, 32, sBytes, 0, 32);
        BigInteger s = new BigInteger(1, sBytes);
        if(s.compareTo(ECKey.CURVE.getN()) >= 0) {
            return false;
        }

        // Let R1 = s⋅G - e⋅A
        ECPoint R1Point = G.getPubKeyPoint().multiply(s).add(A.getPubKeyPoint().multiply(e).negate()).normalize();

        // Fail if is_infinite(R1)
        if(R1Point.isInfinity()) {
            return false;
        }

        ECKey R1 = ECKey.fromPublicOnly(R1Point, true);

        // Let R2 = s⋅B - e⋅C
        ECPoint R2Point = B.getPubKeyPoint().multiply(s).add(C.getPubKeyPoint().multiply(e).negate()).normalize();

        // Fail if is_infinite(R2)
        if(R2Point.isInfinity()) {
            return false;
        }

        ECKey R2 = ECKey.fromPublicOnly(R2Point, true);

        // Fail if e ≠ int(hash_BIP0374/challenge(...))
        BigInteger eExpected = dleqChallenge(A, B, C, R1, R2, m, G);
        if(!e.equals(eExpected)) {
            return false;
        }

        return true;
    }

    /**
     * Calculate the DLEQ challenge hash according to BIP-374.
     *
     * @param A The public key A = a⋅G
     * @param B The public key B
     * @param C The shared secret C = a⋅B
     * @param R1 The first commitment R1 = k⋅G
     * @param R2 The second commitment R2 = k⋅B
     * @param m Optional message (32 bytes or null)
     * @param G The generator point
     * @return The challenge value e
     */
    private static BigInteger dleqChallenge(ECKey A, ECKey B, ECKey C, ECKey R1, ECKey R2, byte[] m, ECKey G) {
        byte[] mPrime = (m == null) ? new byte[0] : m;

        ByteBuffer challengeBuffer = ByteBuffer.allocate(33 + 33 + 33 + 33 + 33 + 33 + mPrime.length);
        challengeBuffer.put(A.getPubKey());
        challengeBuffer.put(B.getPubKey());
        challengeBuffer.put(C.getPubKey());
        challengeBuffer.put(G.getPubKey());
        challengeBuffer.put(R1.getPubKey());
        challengeBuffer.put(R2.getPubKey());
        challengeBuffer.put(mPrime);

        byte[] hash = Utils.taggedHash(DLEQ_TAG_CHALLENGE, challengeBuffer.array());
        return new BigInteger(1, hash);
    }
}
