package com.sparrowwallet.drongo.silentpayments;

import com.sparrowwallet.drongo.crypto.DLEQProof;
import com.sparrowwallet.drongo.crypto.ECKey;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Represents a BIP-375 Silent Payments DLEQ proof.
 *
 * This class wraps a 64-byte DLEQ proof that proves the discrete logarithm
 * equivalency between a public key and an ECDH share, as used in BIP-375
 * Silent Payments for PSBTs.
 */
public class SilentPaymentsDLEQProof {
    private final byte[] proof;

    /**
     * Private constructor that validates and stores the proof bytes.
     *
     * @param proofBytes The 64-byte DLEQ proof
     * @throws IllegalArgumentException if proof is not exactly 64 bytes
     */
    private SilentPaymentsDLEQProof(byte[] proofBytes) {
        if(proofBytes == null) {
            throw new IllegalArgumentException("DLEQ proof cannot be null");
        }
        if(proofBytes.length != 64) {
            throw new IllegalArgumentException("DLEQ proof must be exactly 64 bytes, got " + proofBytes.length);
        }
        this.proof = Arrays.copyOf(proofBytes, proofBytes.length);
    }

    /**
     * Generate a DLEQ proof for Silent Payments according to BIP-375.
     *
     * This method generates a proof that the ECDH share (a⋅B_scan) and the public key (a⋅G)
     * were both generated from the same private key a without revealing a.
     *
     * @param privateKey The private key (a) - either a single input's private key or the sum of the private keys for all eligible inputs
     * @param scanKey The scan public key (B_scan) from the silent payment address
     * @param auxRand 32 bytes of auxiliary random data (should be fresh randomness for each proof)
     * @return A new SilentPaymentsDLEQProof instance
     * @throws IllegalArgumentException if scanKey is not a public-only key, or if auxRand is not 32 bytes
     * @throws InvalidSilentPaymentException if proof generation fails
     */
    public static SilentPaymentsDLEQProof generate(BigInteger privateKey, ECKey scanKey, byte[] auxRand) throws InvalidSilentPaymentException {
        if(auxRand == null || auxRand.length != 32) {
            throw new IllegalArgumentException("Auxiliary random data must be exactly 32 bytes");
        }

        if(!scanKey.isPubKeyOnly()) {
            throw new IllegalArgumentException("Scan key must be a public key only");
        }

        // Generate the proof using BIP-374 GenerateProof with:
        // - a: the private key
        // - B: the scan key
        // - r: auxiliary random data
        // - G: null (uses default secp256k1 generator)
        // - m: null (no message for BIP-375)
        byte[] proofBytes = DLEQProof.generateProof(privateKey, scanKey, auxRand, null, null);

        if(proofBytes == null) {
            throw new InvalidSilentPaymentException("Failed to generate DLEQ proof");
        }

        return new SilentPaymentsDLEQProof(proofBytes);
    }

    /**
     * Create a SilentPaymentsDLEQProof from existing proof bytes.
     *
     * @param proofBytes The 64-byte DLEQ proof
     * @return A new SilentPaymentsDLEQProof instance
     * @throws IllegalArgumentException if proof is not exactly 64 bytes
     */
    public static SilentPaymentsDLEQProof fromBytes(byte[] proofBytes) {
        return new SilentPaymentsDLEQProof(proofBytes);
    }

    /**
     * Verify this DLEQ proof according to BIP-375.
     *
     * This verifies that the ECDH share was generated from the same private key
     * as the public key, without revealing the private key.
     *
     * @param publicKey The public key of the input, or the sum of the public keys of all eligible inputs (A = a⋅G)
     * @param scanKey The scan public key (B_scan) from the silent payment address
     * @param ecdhShare The ECDH share for the input, or the ECDH share for all inputs (C = a⋅B_scan)
     * @return true if the proof is valid, false otherwise
     * @throws IllegalArgumentException if any key is not a public-only key
     */
    public boolean verify(ECKey publicKey, ECKey scanKey, ECKey ecdhShare) {
        if(!publicKey.isPubKeyOnly() || !scanKey.isPubKeyOnly() || !ecdhShare.isPubKeyOnly()) {
            throw new IllegalArgumentException("All keys for verification must be public keys only");
        }

        // Verify the proof using BIP-374 VerifyProof with:
        // - A: the public key
        // - B: the scan key
        // - C: the ECDH share
        // - proof: this proof
        // - G: null (uses default secp256k1 generator)
        // - m: null (no message for BIP-375)
        return DLEQProof.verifyProof(publicKey, scanKey, ecdhShare, proof, null, null);
    }

    /**
     * Get the raw 64-byte proof.
     *
     * @return A copy of the proof bytes
     */
    public byte[] getBytes() {
        return Arrays.copyOf(proof, proof.length);
    }

    @Override
    public boolean equals(Object o) {
        if(this == o) {
            return true;
        }
        if(!(o instanceof SilentPaymentsDLEQProof that)) {
            return false;
        }
        return Arrays.equals(proof, that.proof);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(proof);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        for(byte b : proof) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
