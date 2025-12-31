package com.sparrowwallet.drongo.crypto.musig2;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.crypto.SchnorrSignature;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;

/**
 * MuSig2 Proof-of-Concept Implementation
 *
 * This is a PROOF-OF-CONCEPT implementation of BIP-327 MuSig2 for Taproot multisig.
 * It demonstrates the API design and workflow for 2-of-2 multisig using MuSig2.
 *
 * WARNING: This is NOT production-ready. It uses simplified placeholder crypto
 * for demonstration purposes only. Do NOT use with real funds.
 *
 * BIP-327: https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki
 *
 * MuSig2 Workflow:
 * 1. Key Aggregation: Combine multiple public keys into single aggregated key
 * 2. Round 1: Each signer generates nonces and shares public nonce
 * 3. Round 2: Each signer creates partial signature using aggregated nonce
 * 4. Signature Aggregation: Combine partial signatures into final signature
 *
 * @author Claude (AI Assistant)
 * @version 0.0.1 (PoC)
 * @since 2025-12-30
 */
public class MuSig2 {
    private static final Logger log = LoggerFactory.getLogger(MuSig2.class);
    private static final SecureRandom random = new SecureRandom();

    /**
     * MuSig2 Nonce (Round 1 Message)
     *
     * In production, this contains the public nonce (R1, R2) that signers exchange.
     * The nonce is used to prevent rogue key attacks.
     */
    public static class MuSig2Nonce {
        private final byte[] publicKey1;  // R1
        private final byte[] publicKey2;  // R2

        public MuSig2Nonce(byte[] publicKey1, byte[] publicKey2) {
            this.publicKey1 = publicKey1;
            this.publicKey2 = publicKey2;
        }

        public byte[] getPublicKey1() { return publicKey1; }
        public byte[] getPublicKey2() { return publicKey2; }

        /**
         * Serialize nonce for transmission (base64 in PoC)
         */
        public String serialize() {
            return Base64.getEncoder().encodeToString(publicKey1) + ":" +
                   Base64.getEncoder().encodeToString(publicKey2);
        }

        /**
         * Deserialize nonce from transmission
         */
        public static MuSig2Nonce deserialize(String data) {
            String[] parts = data.split(":");
            if (parts.length != 2) {
                throw new IllegalArgumentException("Invalid nonce format");
            }
            return new MuSig2Nonce(
                Base64.getDecoder().decode(parts[0]),
                Base64.getDecoder().decode(parts[1])
            );
        }
    }

    /**
     * MuSig2 Secret Nonce (Internal)
     *
     * Stores the secret nonce values (k1, k2) used for signing.
     * This is kept private and not shared with other signers.
     *
     * SECURITY: Secret nonces must be kept confidential and used only once!
     */
    public static class SecretNonce {
        private final BigInteger k1;
        private final BigInteger k2;
        private final byte[] publicKey;  // Signer's public key (for validation)

        public SecretNonce(BigInteger k1, BigInteger k2, byte[] publicKey) {
            this.k1 = k1;
            this.k2 = k2;
            this.publicKey = publicKey;
        }

        public BigInteger getK1() { return k1; }
        public BigInteger getK2() { return k2; }
        public byte[] getPublicKey() { return publicKey; }

        /**
         * Zero out sensitive data after use
         */
        public void clear() {
            // In Java, we can't actually zero out BigIntegers, but we can mark them for GC
            // In production, use byte[] instead of BigInteger and zero them out
        }
    }

    /**
     * MuSig2 Complete Nonce (Public + Secret)
     *
     * Contains both the public nonce (for sharing) and secret nonce (for signing).
     * The public nonce is shared with other signers, while the secret nonce is kept private.
     */
    public static class CompleteNonce {
        private final MuSig2Nonce publicNonce;
        private final SecretNonce secretNonce;

        public CompleteNonce(MuSig2Nonce publicNonce, SecretNonce secretNonce) {
            this.publicNonce = publicNonce;
            this.secretNonce = secretNonce;
        }

        public MuSig2Nonce getPublicNonce() { return publicNonce; }
        public SecretNonce getSecretNonce() { return secretNonce; }
    }

    /**
     * MuSig2 Partial Signature (Round 2 Message)
     *
     * Each signer creates a partial signature that is later aggregated.
     */
    public static class PartialSignature {
        private final byte[] R;  // Aggregated public nonce
        private final BigInteger s;  // Partial s value

        public PartialSignature(byte[] R, BigInteger s) {
            this.R = R;
            this.s = s;
        }

        public byte[] getR() { return R; }
        public BigInteger getS() { return s; }

        /**
         * Serialize partial signature for transmission
         */
        public String serialize() {
            return Utils.bytesToHex(R) + ":" + s.toString(16);
        }

        /**
         * Deserialize partial signature from transmission
         */
        public static PartialSignature deserialize(String data) {
            String[] parts = data.split(":");
            if (parts.length != 2) {
                throw new IllegalArgumentException("Invalid partial signature format");
            }
            return new PartialSignature(
                Utils.hexToBytes(parts[0]),
                new BigInteger(parts[1], 16)
            );
        }
    }

    // =========================================================================
    // BIP-327 MuSig2 API (Experimental Implementation)
    // =========================================================================

    /**
     * STEP 1: Aggregate Public Keys
     *
     * Combines multiple participant public keys into a single aggregated public key.
     * This aggregated key becomes the Taproot output key.
     *
     * BIP-327 Section: Key Aggregation
     * Uses MuSig2Core.aggregatePublicKeys() which implements the full BIP-327
     * key aggregation with coefficients.
     *
     * @param publicKeys List of all participant public keys
     * @return Aggregated public key (looks like single Taproot key)
     */
    public static ECKey aggregateKeys(List<ECKey> publicKeys) {
        log.info("MuSig2: Aggregating {} public keys using BIP-327", publicKeys.size());

        // Use BIP-327 key aggregation
        // NOTE: Caller is responsible for sorting keys before calling this method
        // This is to allow testing of different aggregation behaviors
        MuSig2Core.KeyAggContext ctx = MuSig2Core.aggregatePublicKeys(publicKeys);
        ECKey aggregatedKey = ctx.getQ();

        log.info("MuSig2: Aggregated key: {}",
            Utils.bytesToHex(aggregatedKey.getPubKey()).substring(0, 20) + "...");

        return aggregatedKey;
    }

    /**
     * STEP 2: Round 1 - Generate Nonce
     *
     * Each signer generates a nonce (pair of public keys) that will be shared
     * with other signers. The nonce must be deterministic yet unpredictable.
     *
     * BIP-327 Section: Round 1
     * Uses deterministic nonce generation as specified in BIP-327.
     *
     * @param secretKey Signer's secret key
     * @param publicKeys List of all participant public keys
     * @param message Message to be signed (sighash)
     * @return MuSig2 nonce (to be shared with other signers)
     */
    public static CompleteNonce generateRound1Nonce(ECKey secretKey,
                                                     List<ECKey> publicKeys,
                                                     Sha256Hash message) {
        log.info("MuSig2: Generating Round 1 nonce (deterministic, BIP-327)");

        // First compute aggregated key
        ECKey aggregatedKey = aggregateKeys(publicKeys);

        // Generate deterministic nonces (k1, k2) using BIP-327
        BigInteger[] nonces = MuSig2Core.generateDeterministicNonces(
            secretKey, aggregatedKey, message, null);

        BigInteger k1 = nonces[0];
        BigInteger k2 = nonces[1];

        // Compute public nonces: R1 = k1*G, R2 = k2*G
        org.bouncycastle.math.ec.ECPoint G = ECKey.CURVE.getG();
        org.bouncycastle.math.ec.ECPoint R1_point = G.multiply(k1).normalize();
        org.bouncycastle.math.ec.ECPoint R2_point = G.multiply(k2).normalize();

        // Encode as compressed points (33 bytes each: 0x02/0x03 || x-coordinate)
        byte[] R1 = MuSig2Utils.encodeCompressedPoint(R1_point);
        byte[] R2 = MuSig2Utils.encodeCompressedPoint(R2_point);

        // Create public nonce (for sharing)
        MuSig2Nonce publicNonce = new MuSig2Nonce(R1, R2);

        // Create secret nonce (kept private)
        SecretNonce secretNonce = new SecretNonce(k1, k2, secretKey.getPubKey());

        CompleteNonce completeNonce = new CompleteNonce(publicNonce, secretNonce);

        log.info("MuSig2: Generated nonces: R1={}, R2={}",
            Utils.bytesToHex(R1).substring(0, 16) + "...",
            Utils.bytesToHex(R2).substring(0, 16) + "...");

        return completeNonce;
    }

    /**
     * BIP-327 Round 2: Create Partial Signature (BIP-327 Compliant)
     *
     * After receiving Round 1 nonces from all other signers, each signer
     * creates their partial signature using the BIP-327 algorithm.
     *
     * BIP-327 Algorithm:
     * 1. Aggregate all R1 nonces: R1 = sum(R1_i)
     * 2. Aggregate all R2 nonces: R2 = sum(R2_i)
     * 3. Compute nonce coefficient: b = int(hash(MuSig/noncecoef || aggnonce || Q || m)) mod n
     * 4. Compute aggregated nonce: R = R1 + b*R2
     * 5. If R is infinity, set R = G
     * 6. Compute challenge: e = int(hash(BIP0340/challenge || x(R) || Q || m)) mod n
     * 7. Compute key aggregation coefficient: a
     * 8. Compute parity adjustment: g = 1 if Q has even y, else g = n-1
     * 9. Compute partial signature: s = k1 + b*k2 + e*a*g*d mod n
     *
     * @param secretKey Signer's secret key
     * @param secretNonce My secret nonce (k1, k2)
     * @param publicKeys List of all participant public keys
     * @param publicNonces Public nonces from all signers (including mine)
     * @param message Message to be signed (sighash)
     * @return Partial signature (to be shared with other signers)
     */

    /**
     * Helper class to hold aggregated nonce data
     */
    private static class AggregatedNonces {
        final org.bouncycastle.math.ec.ECPoint R1_agg;
        final org.bouncycastle.math.ec.ECPoint R2_agg;
        final byte[] aggnonce;

        AggregatedNonces(org.bouncycastle.math.ec.ECPoint R1_agg,
                        org.bouncycastle.math.ec.ECPoint R2_agg,
                        byte[] aggnonce) {
            this.R1_agg = R1_agg;
            this.R2_agg = R2_agg;
            this.aggnonce = aggnonce;
        }
    }

    /**
     * BIP-327: Aggregate all nonces (R1 and R2)
     *
     * @param publicNonces Public nonces from all signers
     * @return AggregatedNonces containing R1_agg, R2_agg, and encoded aggnonce
     */
    private static AggregatedNonces aggregateNonces(List<MuSig2Nonce> publicNonces) {
        // BIP-327: Aggregate all R1 nonces
        org.bouncycastle.math.ec.ECPoint R1_agg = null;
        for (MuSig2Nonce nonce : publicNonces) {
            org.bouncycastle.math.ec.ECPoint point = ECKey.CURVE.getCurve().decodePoint(nonce.getPublicKey1());
            R1_agg = (R1_agg == null) ? point : R1_agg.add(point);
        }
        R1_agg = R1_agg.normalize();

        // BIP-327: Aggregate all R2 nonces
        org.bouncycastle.math.ec.ECPoint R2_agg = null;
        for (MuSig2Nonce nonce : publicNonces) {
            org.bouncycastle.math.ec.ECPoint point = ECKey.CURVE.getCurve().decodePoint(nonce.getPublicKey2());
            R2_agg = (R2_agg == null) ? point : R2_agg.add(point);
        }
        R2_agg = R2_agg.normalize();

        log.debug("Aggregated R1: {}, R2: {}",
            Utils.bytesToHex(R1_agg.getAffineXCoord().getEncoded()).substring(0, 16) + "...",
            Utils.bytesToHex(R2_agg.getAffineXCoord().getEncoded()).substring(0, 16) + "...");

        // BIP-327: Encode aggnonce as R1 || R2 (compressed)
        byte[] aggnonce = new byte[66];
        byte[] R1_encoded = MuSig2Utils.encodeCompressedPoint(R1_agg);
        byte[] R2_encoded = MuSig2Utils.encodeCompressedPoint(R2_agg);
        System.arraycopy(R1_encoded, 0, aggnonce, 0, 33);
        System.arraycopy(R2_encoded, 0, aggnonce, 33, 33);

        return new AggregatedNonces(R1_agg, R2_agg, aggnonce);
    }

    /**
     * BIP-327: Compute nonce coefficient b
     *
     * b = int(hash("MuSig/noncecoef" || aggnonce || x(Q) || m)) mod n
     *
     * @param aggnonce Encoded aggregated nonce (66 bytes)
     * @param Q Aggregated public key point
     * @param message Message to be signed
     * @param n Curve order
     * @return Nonce coefficient b
     */
    private static BigInteger computeNonceCoefficient(byte[] aggnonce, org.bouncycastle.math.ec.ECPoint Q,
                                                      Sha256Hash message, BigInteger n) throws java.io.IOException {
        ByteArrayOutputStream bInput = new ByteArrayOutputStream();
        bInput.write(aggnonce, 0, aggnonce.length);
        // BIP-327: x(Q) should use GetXonlyPubkey (with_even_y applied)
        byte[] Q_xonly = MuSig2Utils.getXonlyPubkey(Q);
        bInput.write(Q_xonly);
        bInput.write(message.getBytes());

        byte[] bBytes = Utils.taggedHash("MuSig/noncecoef", bInput.toByteArray());
        BigInteger b = new BigInteger(1, bBytes).mod(n);

        log.debug("Nonce coefficient b: {}", b.toString(16).substring(0, Math.min(8, b.toString(16).length())) + "...");

        return b;
    }

    /**
     * BIP-327: Compute aggregated nonce point R
     *
     * R = R1 + b*R2
     * If R is infinity, set R = G
     *
     * @param aggnonces Aggregated nonce data
     * @param b Nonce coefficient
     * @return R point and x-coordinate
     */
    private static org.bouncycastle.math.ec.ECPoint computeRpoint(AggregatedNonces aggnonces, BigInteger b) {
        org.bouncycastle.math.ec.ECPoint G = ECKey.CURVE.getG();

        // BIP-327: R = R1 + b*R2
        org.bouncycastle.math.ec.ECPoint R = aggnonces.R1_agg.add(aggnonces.R2_agg.multiply(b)).normalize();

        // BIP-327: If R is infinity, set R = G
        if (R.isInfinity()) {
            log.warn("R is infinity, using generator G instead");
            R = G;
        }

        byte[] xR = R.getAffineXCoord().getEncoded();
        log.debug("Aggregated nonce R: {}", Utils.bytesToHex(xR).substring(0, 16) + "...");

        return R;
    }

    /**
     * BIP-327: Compute challenge e
     *
     * e = int(hash("BIP0340/challenge" || x(R) || x(Q) || m)) mod n
     *
     * @param R Aggregated nonce point
     * @param Q Aggregated public key point
     * @param message Message to be signed
     * @param n Curve order
     * @return Challenge e
     */
    private static BigInteger computeChallengeForSigning(org.bouncycastle.math.ec.ECPoint R,
                                                         org.bouncycastle.math.ec.ECPoint Q,
                                                         Sha256Hash message, BigInteger n) throws java.io.IOException {
        byte[] xR = R.getAffineXCoord().getEncoded();

        ByteArrayOutputStream eInput = new ByteArrayOutputStream();
        eInput.write(xR);
        // BIP-327: GetXonlyPubkey applies with_even_y to get x-coordinate with even y
        byte[] Q_xonly = MuSig2Utils.getXonlyPubkey(Q);
        eInput.write(Q_xonly);
        eInput.write(message.getBytes());

        byte[] eBytes = Utils.taggedHash("BIP0340/challenge", eInput.toByteArray());
        BigInteger e = new BigInteger(1, eBytes).mod(n);

        log.debug("Challenge e: {}", e.toString(16).substring(0, Math.min(8, e.toString(16).length())) + "...");

        return e;
    }

    /**
     * BIP-327: Compute parity adjustment factor g_v
     *
     * g_v = 1 if has_even_y(Q), otherwise g_v = -1 mod n
     *
     * @param Q Aggregated public key point
     * @param n Curve order
     * @return Parity adjustment factor (1 or n-1)
     */
    private static BigInteger computeParityFactor(org.bouncycastle.math.ec.ECPoint Q, BigInteger n) {
        return MuSig2Utils.parityFactor(Q, n);
    }

    /**
     * BIP-327: Adjust secret nonces based on R's y-parity
     *
     * If R has odd y:
     *   k1 = n - k1'
     *   k2 = n - k2'
     * Otherwise:
     *   k1 = k1'
     *   k2 = k2'
     *
     * @param R Aggregated nonce point
     * @param k1_prime Original k1
     * @param k2_prime Original k2
     * @param n Curve order
     * @return Array with [k1, k2]
     */
    private static BigInteger[] computeAdjustedSecretNonces(org.bouncycastle.math.ec.ECPoint R,
                                                             BigInteger k1_prime, BigInteger k2_prime,
                                                             BigInteger n) {
        BigInteger k1, k2;

        if (MuSig2Utils.hasEvenY(R)) {
            // R has even y, use k1', k2' as-is
            k1 = k1_prime;
            k2 = k2_prime;
            log.debug("R has EVEN y, using k1=k1', k2=k2'");
        } else {
            // R has odd y, negate: k1 = n - k1', k2 = n - k2'
            k1 = n.subtract(k1_prime).mod(n);
            k2 = n.subtract(k2_prime).mod(n);
            log.debug("R has ODD y, using k1=n-k1', k2=n-k2'");
        }

        return new BigInteger[] { k1, k2 };
    }

    /**
     * BIP-327 Round 2: Create Partial Signature
     *
     * Simplified implementation using helper methods.
     */
    public static PartialSignature signRound2BIP327(ECKey secretKey,
                                                      SecretNonce secretNonce,
                                                      List<ECKey> publicKeys,
                                                      List<MuSig2Nonce> publicNonces,
                                                      Sha256Hash message) {
        log.info("MuSig2: Creating Round 2 partial signature (BIP-327 compliant)");

        try {
            BigInteger n = ECKey.CURVE.getN();

            // BIP-327: Aggregate nonces (R1 and R2)
            AggregatedNonces aggnonces = aggregateNonces(publicNonces);

            // BIP-327: Compute aggregated key Q with context
            MuSig2Core.KeyAggContext keyaggCtx = MuSig2Core.aggregatePublicKeys(publicKeys);
            ECKey aggregatedKey = keyaggCtx.getQ();
            org.bouncycastle.math.ec.ECPoint Q = aggregatedKey.getPubKeyPoint().normalize();
            BigInteger gacc = keyaggCtx.getGacc();

            // BIP-327: Compute nonce coefficient b
            BigInteger b = computeNonceCoefficient(aggnonces.aggnonce, Q, message, n);

            // BIP-327: Compute aggregated nonce point R
            org.bouncycastle.math.ec.ECPoint R = computeRpoint(aggnonces, b);
            byte[] xR = R.getAffineXCoord().getEncoded();

            // BIP-327: Compute challenge e
            BigInteger e = computeChallengeForSigning(R, Q, message, n);

            // BIP-327: Compute key aggregation coefficient a
            ECKey myPublicKey = ECKey.fromPublicOnly(secretKey.getPubKey());
            BigInteger a = MuSig2Core.computeKeyAggCoefficient(myPublicKey, publicKeys);
            log.debug("Key aggregation coefficient a: {}",
                a.toString(16).substring(0, Math.min(8, a.toString(16).length())) + "...");

            // BIP-327: Get secret key d' = int(sk)
            BigInteger d_prime = secretKey.getPrivKey();
            log.debug("Secret key d' = int(sk) = {}", d_prime.toString(16).substring(0, 8) + "...");

            // BIP-327: Compute parity adjustment g_v
            BigInteger g_v = computeParityFactor(Q, n);
            log.debug("Parity adjustment g_v: {} (Q has {} y, gacc: {})",
                g_v.equals(BigInteger.ONE) ? "1" : "n-1",
                MuSig2Utils.hasEvenY(Q) ? "EVEN" : "ODD",
                gacc.toString(16).substring(0, Math.min(8, gacc.toString(16).length())) + "...");

            // BIP-327: Compute d = g_v ⋅ gacc ⋅ d' mod n
            BigInteger d = g_v.multiply(gacc).mod(n).multiply(d_prime).mod(n);
            log.debug("Final secret key factor d = g_v ⋅ gacc ⋅ d' mod n");

            // BIP-327: Adjust secret nonces based on R's y-parity
            BigInteger k1_prime = secretNonce.getK1();
            BigInteger k2_prime = secretNonce.getK2();
            BigInteger[] adjusted = computeAdjustedSecretNonces(R, k1_prime, k2_prime, n);
            BigInteger k1 = adjusted[0];
            BigInteger k2 = adjusted[1];

            // BIP-327: Compute partial signature: s = k1 + b*k2 + e*a*d mod n
            BigInteger term1 = k1;
            BigInteger term2 = b.multiply(k2).mod(n);
            BigInteger term3 = e.multiply(a).mod(n).multiply(d).mod(n);
            BigInteger s = term1.add(term2).add(term3).mod(n);

            log.info("MuSig2: Created partial signature: s={}", s.toString(16).substring(0, 8) + "...");

            return new PartialSignature(xR, s);

        } catch (Exception ex) {
            log.error("Error creating partial signature", ex);
            throw new RuntimeException("Failed to create partial signature", ex);
        }
    }

    /**
     * STEP 4: Aggregate Signatures
     *
     * Combines partial signatures from all signers into the final Schnorr signature.
     * The final signature is valid for the aggregated public key.
     *
     * BIP-327 Section: Signature Aggregation
     *
     * Algorithm:
     * - R is the aggregated nonce (same for all partial signatures)
     * - s = sum of all partial s values mod n
     *
     * @param partialSignatures Partial signatures from all signers
     * @return Final aggregated Schnorr signature
     */
    public static SchnorrSignature aggregateSignatures(List<PartialSignature> partialSignatures) {
        log.info("MuSig2: Aggregating {} partial signatures (BIP-327)", partialSignatures.size());

        if (partialSignatures.isEmpty()) {
            throw new IllegalArgumentException("Cannot aggregate empty list of partial signatures");
        }

        try {
            // BIP-327: All partial signatures should have the same R (aggregated nonce)
            byte[] R = partialSignatures.get(0).getR();

            // Verify all partial signatures have the same R
            for (int i = 1; i < partialSignatures.size(); i++) {
                if (!Arrays.equals(R, partialSignatures.get(i).getR())) {
                    log.warn("Partial signature {} has different R value", i);
                }
            }

            // BIP-327: Aggregate s values: s = s_1 + s_2 + ... + s_n (mod n)
            BigInteger aggregatedS = BigInteger.ZERO;
            for (PartialSignature sig : partialSignatures) {
                aggregatedS = aggregatedS.add(sig.getS());
            }

            // Modulo by curve order
            aggregatedS = aggregatedS.mod(ECKey.CURVE.getN());

            log.debug("Aggregated signature s: {}", aggregatedS.toString(16).substring(0, 8) + "...");

            // Create final Schnorr signature
            BigInteger R_bigint = new BigInteger(1, R);
            SchnorrSignature finalSig = new SchnorrSignature(R_bigint, aggregatedS);

            log.info("MuSig2: Final BIP-327 signature: {}...",
                Utils.bytesToHex(finalSig.encode()).substring(0, 16));

            return finalSig;

        } catch (Exception e) {
            log.error("Error aggregating BIP-327 signatures", e);
            throw new RuntimeException("Failed to aggregate signatures: " + e.getMessage(), e);
        }
    }

    // =========================================================================
    // Convenience Methods for 2-of-2 Signing
    // =========================================================================

    /**
     * Complete 2-of-2 MuSig2 Signing Flow (Demonstration)
     *
     * This method demonstrates the complete MuSig2 workflow for a 2-of-2
     * multisig signature. In production, the two signers would communicate
     * the Round 1 and Round 2 messages over a network.
     *
     * @param secretKey1 First signer's secret key
     * @param secretKey2 Second signer's secret key
     * @param message Message to sign (typically transaction sighash)
     * @return Aggregated Schnorr signature valid for the 2-of-2 multisig
     */
    public static SchnorrSignature sign2of2(ECKey secretKey1,
                                            ECKey secretKey2,
                                            Sha256Hash message) {
        log.info("MuSig2: Starting 2-of-2 signing flow");

        // Extract public keys
        ECKey pubKey1 = ECKey.fromPublicOnly(secretKey1.getPubKey());
        ECKey pubKey2 = ECKey.fromPublicOnly(secretKey2.getPubKey());
        List<ECKey> publicKeys = new ArrayList<>(Arrays.asList(pubKey1, pubKey2));

        // BIP-327: Sort keys before aggregation
        MuSig2Core.sortPublicKeys(publicKeys);

        // STEP 1: Aggregate public keys
        ECKey aggregatedKey = aggregateKeys(publicKeys);
        log.info("MuSig2: Aggregated Taproot key: {}",
            Utils.bytesToHex(aggregatedKey.getPubKey()));

        // STEP 2: Round 1 - Generate nonces (BIP-327 compliant)
        CompleteNonce completeNonce1 = generateRound1Nonce(secretKey1, publicKeys, message);
        CompleteNonce completeNonce2 = generateRound1Nonce(secretKey2, publicKeys, message);

        // Collect public nonces from all signers
        List<MuSig2Nonce> publicNonces = Arrays.asList(
            completeNonce1.getPublicNonce(),
            completeNonce2.getPublicNonce()
        );

        // STEP 3: Round 2 - Create partial signatures (BIP-327 compliant)
        // Signer 1 creates partial signature
        PartialSignature partial1 = signRound2BIP327(
            secretKey1,
            completeNonce1.getSecretNonce(),
            publicKeys,
            publicNonces,
            message
        );

        // Signer 2 creates partial signature
        PartialSignature partial2 = signRound2BIP327(
            secretKey2,
            completeNonce2.getSecretNonce(),
            publicKeys,
            publicNonces,
            message
        );

        // STEP 4: Aggregate signatures
        List<PartialSignature> partialSigs = Arrays.asList(partial1, partial2);
        SchnorrSignature finalSig = aggregateSignatures(partialSigs);

        log.info("MuSig2: 2-of-2 signing complete!");
        log.info("MuSig2: Final signature: {}",
            Utils.bytesToHex(finalSig.encode()));

        return finalSig;
    }

    /**
     * Helper class to hold parsed signature components
     */
    private static class ParsedSignature {
        final BigInteger r;
        final BigInteger s;
        final byte[] rBytes;

        ParsedSignature(BigInteger r, BigInteger s, byte[] rBytes) {
            this.r = r;
            this.s = s;
            this.rBytes = rBytes;
        }
    }

    /**
     * BIP-340: Parse and validate signature components
     *
     * Extracts r and s from signature and validates that r < p and s < n
     *
     * @param signature Schnorr signature
     * @return ParsedSignature with r, s, and rBytes, or null if invalid
     */
    private static ParsedSignature parseSignatureInput(SchnorrSignature signature) {
        BigInteger r = signature.r;
        BigInteger s = signature.s;

        // BIP-340: Verify r < p and s < n
        BigInteger p = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
        if (r.compareTo(p) >= 0 || s.compareTo(ECKey.CURVE.getN()) >= 0) {
            log.warn("Signature values out of range: r >= p or s >= n");
            return null;
        }

        byte[] rBytes = Utils.bigIntegerToBytes(r, 32);
        return new ParsedSignature(r, s, rBytes);
    }

    /**
     * BIP-340: Compute challenge e for verification
     *
     * e = int(hash("BIP0340/challenge" || r || P || m)) mod n
     *
     * @param rBytes Encoded r value (32 bytes)
     * @param Q Aggregated public key point
     * @param message Message that was signed
     * @return Challenge e
     */
    private static BigInteger computeChallengeForVerify(byte[] rBytes, org.bouncycastle.math.ec.ECPoint Q,
                                                        Sha256Hash message) throws java.io.IOException {
        // BIP-327: P uses x-only with even y
        byte[] pubKeyBytes = MuSig2Utils.getXonlyPubkey(Q);

        ByteArrayOutputStream challengeInput = new ByteArrayOutputStream();
        challengeInput.write(rBytes);
        challengeInput.write(pubKeyBytes);
        challengeInput.write(message.getBytes());

        byte[] eBytes = Utils.taggedHash("BIP0340/challenge", challengeInput.toByteArray());
        BigInteger e = new BigInteger(1, eBytes).mod(ECKey.CURVE.getN());

        log.debug("Challenge e: {}", e.toString(16).substring(0, 8) + "...");
        log.debug("R (x): {}", Utils.bytesToHex(rBytes).substring(0, 8) + "...");
        log.debug("P (x): {}", Utils.bytesToHex(pubKeyBytes).substring(0, 16) + "...");

        return e;
    }

    /**
     * BIP-340: Verify equation s*G = R + e*P
     *
     * @param s Signature s value
     * @param r Signature r value
     * @param e Challenge
     * @param Q Aggregated public key point
     * @return true if equation holds, false otherwise
     */
    private static boolean verifyEquation(BigInteger s, BigInteger r, BigInteger e,
                                         org.bouncycastle.math.ec.ECPoint Q) {
        org.bouncycastle.math.ec.ECPoint G = ECKey.CURVE.getG();

        // Left side: s*G
        org.bouncycastle.math.ec.ECPoint sG = G.multiply(s).normalize();

        // Right side: R + e*P
        org.bouncycastle.math.ec.ECPoint R_point = lift_x_even_y(r);
        if (R_point == null) {
            log.warn("Cannot lift x-coordinate to point");
            return false;
        }
        R_point = R_point.normalize();

        // P is the aggregated public key with even y
        org.bouncycastle.math.ec.ECPoint P = MuSig2Utils.withEvenY(Q);

        log.debug("Aggregated key P (after with_even_y): x={}, y parity={}",
            P.getAffineXCoord().toBigInteger().toString(16).substring(0, 16) + "...",
            P.getAffineYCoord().toBigInteger().mod(BigInteger.TWO).equals(BigInteger.ZERO) ? "EVEN" : "ODD");

        org.bouncycastle.math.ec.ECPoint eP = P.multiply(e).normalize();
        org.bouncycastle.math.ec.ECPoint rightSide = R_point.add(eP).normalize();

        log.debug("sG (x): {}", sG.getAffineXCoord().toBigInteger().toString(16).substring(0, 8) + "...");
        log.debug("R+eP (x): {}", rightSide.getAffineXCoord().toBigInteger().toString(16).substring(0, 8) + "...");

        boolean isValid = sG.equals(rightSide);

        if (!isValid) {
            log.warn("MuSig2: Signature verification FAILED");
            log.warn("  sG.x      = {}", sG.getAffineXCoord().toBigInteger().toString(16));
            log.warn("  R+eP.x    = {}", rightSide.getAffineXCoord().toBigInteger().toString(16));
            log.warn("  R.x       = {}", R_point.getAffineXCoord().toBigInteger().toString(16));
            log.warn("  P.x       = {}", P.getAffineXCoord().toBigInteger().toString(16));
            log.warn("  P.y parity = {}", P.getAffineYCoord().toBigInteger().mod(BigInteger.TWO).equals(BigInteger.ZERO) ? "EVEN" : "ODD");
            log.warn("  e         = {}", e.toString(16));
            log.warn("  s         = {}", s.toString(16));
        } else {
            log.info("MuSig2: Signature verification PASSED");
        }

        return isValid;
    }

    /**
     * Verify MuSig2 Signature
     *
     * Verifies that a MuSig2 aggregated signature is valid for the
     * aggregated public key and message.
     *
     * BIP-327 Section: Verification
     *
     * Algorithm (BIP-340 Schnorr verification):
     * 1. Compute challenge: e = SHA256(R || P || m)
     * 2. Verify that: s*G = R + e*P
     *    where G is the generator point, P is the aggregated public key
     *
     * @param signature Aggregated Schnorr signature
     * @param aggregatedKey Aggregated public key (x-only)
     * @param message Message that was signed
     * @return True if signature is valid
     */
    public static boolean verify(SchnorrSignature signature,
                                  ECKey aggregatedKey,
                                  Sha256Hash message) {
        log.info("MuSig2: Verifying BIP-327 signature (BIP-340)");

        try {
            // BIP-340: Parse and validate signature components
            ParsedSignature parsed = parseSignatureInput(signature);
            if (parsed == null) {
                return false;
            }

            // BIP-327: Get aggregated public key point
            org.bouncycastle.math.ec.ECPoint Q = aggregatedKey.getPubKeyPoint().normalize();

            // BIP-340: Compute challenge e
            BigInteger e = computeChallengeForVerify(parsed.rBytes, Q, message);

            // BIP-340: Verify equation s*G = R + e*P
            return verifyEquation(parsed.s, parsed.r, e, Q);

        } catch (Exception ex) {
            log.error("Error verifying BIP-327 signature", ex);
            return false;
        }
    }

    /**
     * BIP-327: Compute original aggregated Q without normalization
     *
     * This duplicates the key aggregation logic from MuSig2Core but
     * returns the raw aggregated point (with potentially odd y).
     *
     * @param publicKeys List of all signer public keys
     * @return Original aggregated point (may have odd y)
     */
    private static org.bouncycastle.math.ec.ECPoint computeOriginalQ(List<ECKey> publicKeys) {
        log.debug("[wasQNegated] Computing original Q. Number of keys: {}", publicKeys.size());

        org.bouncycastle.math.ec.ECPoint aggregatedPoint = null;

        // Precompute L once (consistent for all keys)
        byte[] L = MuSig2Core.hashKeys(publicKeys);
        ECKey pk2 = MuSig2Core.getSecondKey(publicKeys);

        if (pk2 != null) {
            log.debug("[wasQNegated] Second key (pk2): {}",
                Utils.bytesToHex(pk2.getPubKey()).substring(0, 20) + "...");
        }

        for (int i = 0; i < publicKeys.size(); i++) {
            ECKey signerKey = publicKeys.get(i);
            org.bouncycastle.math.ec.ECPoint P_i = signerKey.getPubKeyPoint();

            // Compute coefficient a_i
            BigInteger a_i;
            if (pk2 != null && signerKey.equals(pk2)) {
                a_i = BigInteger.ONE;
                log.debug("[wasQNegated]   Key[{}] coefficient: 1 (is second key)", i);
            } else {
                byte[] pkBytes = signerKey.getPubKey();
                byte[] hashInput = new byte[L.length + pkBytes.length];
                System.arraycopy(L, 0, hashInput, 0, L.length);
                System.arraycopy(pkBytes, 0, hashInput, L.length, pkBytes.length);
                byte[] hashBytes = Utils.taggedHash("KeyAgg coefficient", hashInput);
                a_i = new BigInteger(1, hashBytes).mod(ECKey.CURVE.getN());
                log.debug("[wasQNegated]   Key[{}] coefficient: {}", i,
                    a_i.toString(16).substring(0, Math.min(8, a_i.toString(16).length())) + "...");
            }

            // Multiply point by coefficient
            org.bouncycastle.math.ec.ECPoint adjustedPoint = P_i.multiply(a_i);

            // Add to aggregate
            if (aggregatedPoint == null) {
                aggregatedPoint = adjustedPoint;
            } else {
                aggregatedPoint = aggregatedPoint.add(adjustedPoint);
            }
        }

        return aggregatedPoint != null ? aggregatedPoint.normalize() : null;
    }

    /**
     * BIP-327: Verify Q consistency
     *
     * Checks that the recomputed Q matches the normalized Q
     *
     * @param originalQ Recomputed original Q
     * @param normalizedQ The normalized aggregated key Q (with even y)
     * @return true if x-coordinates match
     */
    private static boolean verifyQConsistency(org.bouncycastle.math.ec.ECPoint originalQ,
                                             org.bouncycastle.math.ec.ECPoint normalizedQ) {
        boolean x_matches = originalQ.getAffineXCoord().equals(normalizedQ.getAffineXCoord());
        log.debug("[wasQNegated] Q x-coordinates match: {}", x_matches);

        if (!x_matches) {
            log.error("[wasQNegated] WARNING: Recomputed Q doesn't match normalized Q!");
            log.error("[wasQNegated]   This suggests keys are not in the expected order!");
        }

        return x_matches;
    }

    /**
     * Helper: Lift x-coordinate to elliptic curve point with even y
     *
     * BIP-340 lift_x algorithm: Given an x-coordinate, find the point P on the curve
     * with x-coordinate P.x = x and P.y being a quadratic residue (even y).
     *
     * @param x x-coordinate as BigInteger
     * @return Point with x-coordinate x and even y, or null if no such point exists
     */
    private static org.bouncycastle.math.ec.ECPoint lift_x_even_y(BigInteger x) {
        try {
            byte[] xBytes = Utils.bigIntegerToBytes(x, 32);

            // Try to decode with 0x02 prefix (even y)
            byte[] encodedPoint = new byte[33];
            encodedPoint[0] = 0x02;
            System.arraycopy(xBytes, 0, encodedPoint, 1, 32);

            org.bouncycastle.math.ec.ECPoint point = ECKey.CURVE.getCurve().decodePoint(encodedPoint);

            // Verify the point is on the curve
            if (!point.isValid()) {
                log.warn("Decoded point is not valid on curve");
                return null;
            }

            return point;
        } catch (IllegalArgumentException e) {
            // If x is not a valid x-coordinate on the curve
            log.warn("x-coordinate {} is not on curve: {}", x.toString(16).substring(0, 8), e.getMessage());
            return null;
        } catch (Exception e) {
            log.error("Failed to lift x-coordinate to point", e);
            return null;
        }
    }

    /**
     * Helper: Detect if Q was negated during aggregation (with_even_y)
     *
     * During key aggregation, if the original Q has odd y, it is negated to Q' = -Q (with even y).
     * This method detects whether this negation occurred by comparing the normalized Q
     * with what the original Q would have been.
     *
     * @param publicKeys List of all signer public keys
     * @param normalizedQ The normalized aggregated key Q (with even y)
     * @return true if Q was negated during aggregation (original Q had odd y)
     */
    private static boolean wasQNegated(List<ECKey> publicKeys, org.bouncycastle.math.ec.ECPoint normalizedQ) {
        try {
            // Log input key order
            log.debug("[wasQNegated] Checking if Q was negated. Number of keys: {}", publicKeys.size());
            for (int i = 0; i < publicKeys.size(); i++) {
                log.debug("[wasQNegated]   Key[{}]: {}", i,
                    Utils.bytesToHex(publicKeys.get(i).getPubKey()).substring(0, 20) + "...");
            }

            // BIP-327: Compute original Q (without normalization)
            org.bouncycastle.math.ec.ECPoint originalQ = computeOriginalQ(publicKeys);
            if (originalQ == null) {
                return false;
            }

            // BIP-327: Check if original Q had odd y
            boolean originalQ_has_odd_y = !MuSig2Utils.hasEvenY(originalQ);

            log.debug("[wasQNegated] Original Q y-parity: {}", originalQ_has_odd_y ? "ODD (will negate)" : "EVEN (no negate)");
            log.debug("[wasQNegated] Normalized Q x: {}",
                normalizedQ.getAffineXCoord().toBigInteger().toString(16).substring(0, 16) + "...");
            log.debug("[wasQNegated] Recomputed Q x: {}",
                originalQ.getAffineXCoord().toBigInteger().toString(16).substring(0, 16) + "...");

            // BIP-327: Verify Q consistency
            verifyQConsistency(originalQ, normalizedQ);

            return originalQ_has_odd_y;

        } catch (Exception e) {
            log.error("Error detecting Q negation", e);
            // If we can't determine, assume Q was not negated
            return false;
        }
    }
}
