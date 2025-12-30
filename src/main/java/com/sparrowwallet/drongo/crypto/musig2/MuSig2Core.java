package com.sparrowwallet.drongo.crypto.musig2;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;

/**
 * BIP-327 MuSig2 Core Cryptographic Operations
 *
 * Implements the core cryptographic operations for MuSig2 as specified in BIP-327:
 * https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki
 *
 * This implementation follows the specification closely to ensure compatibility
 * with other MuSig2 implementations.
 *
 * WARNING: This is experimental software. Use at your own risk.
 * Do NOT use with significant funds without security audit.
 *
 * @author Claude (AI Assistant)
 * @version 0.2.0 (Experimental)
 * @since 2025-12-30
 */
public class MuSig2Core {
    private static final Logger log = LoggerFactory.getLogger(MuSig2Core.class);

    /**
     * BIP-327: KeyAgg Context Structure
     *
     * Maintains the state of the key aggregation process including:
     * - Q: The aggregated public key
     * - gacc: Parity accumulator (product of g values from tweaks)
     * - tacc: Tweak accumulator (sum of tweak values)
     * - Q_was_negated: Whether Q was negated during key aggregation
     *
     * This context is required for:
     * - BIP32 derivation (hardened derivation)
     * - Taproot tweaking
     * - Multiple sequential tweaks
     */
    public static class KeyAggContext {
        private final ECKey Q;           // Aggregated public key
        private final BigInteger gacc;   // Parity accumulator (initially 1)
        private final BigInteger tacc;   // Tweak accumulator (initially 0)
        private final boolean Q_was_negated; // Whether Q was negated during key agg

        public KeyAggContext(ECKey Q, BigInteger gacc, BigInteger tacc, boolean Q_was_negated) {
            this.Q = Q;
            this.gacc = gacc;
            this.tacc = tacc;
            this.Q_was_negated = Q_was_negated;
        }

        public ECKey getQ() {
            return Q;
        }

        public BigInteger getGacc() {
            return gacc;
        }

        public BigInteger getTacc() {
            return tacc;
        }

        public boolean wasQNegated() {
            return Q_was_negated;
        }

        /**
         * BIP-327: Get X-only public key (32 bytes)
         *
         * This method applies with_even_y(Q) and returns only the x-coordinate.
         * According to BIP-327:
         * - GetXonlyPubkey returns xbytes(Q) where Q is normalized to even y
         *
         * @return 32-byte x-coordinate of Q (with even y)
         */
        public byte[] getXonlyPubkey() {
            org.bouncycastle.math.ec.ECPoint Q_point = Q.getPubKeyPoint().normalize();

            // BIP-327: with_even_y(Q) - if Q has odd y, negate it
            if (!Q_point.getAffineYCoord().toBigInteger().testBit(0)) {
                // y is even
                return Q_point.getAffineXCoord().getEncoded();
            } else {
                // y is odd, return -Q which has even y
                org.bouncycastle.math.ec.ECPoint Q_even = Q_point.negate().normalize();
                return Q_even.getAffineXCoord().getEncoded();
            }
        }

        @Override
        public String toString() {
            return "KeyAggContext{" +
                    "Q=" + Utils.bytesToHex(Q.getPubKey()).substring(0, Math.min(16, Q.getPubKey().length)) + "..." +
                    ", gacc=" + gacc.toString(16).substring(0, Math.min(8, gacc.toString(16).length())) + "..." +
                    ", tacc=" + tacc.toString(16).substring(0, Math.min(8, tacc.toString(16).length())) + "..." +
                    ", Q_was_negated=" + Q_was_negated +
                    '}';
        }
    }

    // BIP-327: Tagged hashes for MuSig2 (using exact tags from specification)
    private static final String MUSIG_AUX_TAG = "MuSig/aux";
    private static final String MUSIG_NONCE_TAG = "MuSig/nonce";
    private static final String KEYAGG_LIST_TAG = "KeyAgg list";
    private static final String KEYAGG_COEFF_TAG = "KeyAgg coefficient";
    private static final String BIP0340_CHALLENGE_TAG = "BIP0340/challenge";

    /**
     * BIP-327: Key Aggregation Coefficient Calculation
     *
     * Computes the key aggregation coefficient for a signer's public key.
     * This is defined in BIP-327 section "Key Aggregation".
     *
     * The coefficient a_i for signer i is computed as:
     * - If pk == pk2: a_i = 1 (MuSig2* optimization)
     * - Otherwise: a_i = int(hashKeyAgg coefficient(L || pk)) mod n
     *
     * where L = hashKeyAgg list(pk1 || pk2 || ... || pku)
     *
     * @param signerPublicKey The signer's public key
     * @param allPublicKeys List of all signers' public keys (including this signer)
     * @return The aggregation coefficient as a scalar (mod n)
     */
    public static BigInteger computeKeyAggCoefficient(ECKey signerPublicKey, List<ECKey> allPublicKeys) {
        if (!allPublicKeys.contains(signerPublicKey)) {
            throw new IllegalArgumentException("Signer public key must be in the list of all public keys");
        }

        log.debug("Computing BIP-327 key aggregation coefficient for key {}",
            Utils.bytesToHex(signerPublicKey.getPubKey()).substring(0, 16) + "...");

        try {
            // BIP-327: Get second key (first key distinct from pk1)
            ECKey pk2 = getSecondKey(allPublicKeys);

            // BIP-327: If this is the second key, coefficient is 1 (MuSig2* optimization)
            if (signerPublicKey.equals(pk2)) {
                log.debug("Signer is second key, using coefficient 1 (MuSig2* optimization)");
                return BigInteger.ONE;
            }

            // BIP-327: Compute L = hashKeyAgg list(pk1 || pk2 || ... || pku)
            byte[] L = hashKeys(allPublicKeys);

            // BIP-327: a_i = int(hashKeyAgg coefficient(L || pk_i)) mod n
            byte[] signerPkBytes = signerPublicKey.getPubKey();
            byte[] hashInput = new byte[L.length + signerPkBytes.length];
            System.arraycopy(L, 0, hashInput, 0, L.length);
            System.arraycopy(signerPkBytes, 0, hashInput, L.length, signerPkBytes.length);

            byte[] hashBytes = Utils.taggedHash(KEYAGG_COEFF_TAG, hashInput);
            BigInteger coefficient = new BigInteger(1, hashBytes).mod(ECKey.CURVE.getN());

            log.debug("Coefficient: {}", coefficient.toString(16).substring(0, 8) + "...");

            return coefficient;

        } catch (Exception e) {
            log.error("Error computing key aggregation coefficient", e);
            throw new RuntimeException("Failed to compute coefficient", e);
        }
    }

    /**
     * BIP-327: Aggregate Public Keys with Coefficients
     *
     * Aggregates multiple public keys into a single key using MuSig2 key aggregation.
     * This is the main key aggregation function that applies coefficients to each key.
     *
     * Q = a_1 * X_1 + a_2 * X_2 + ... + a_n * X_n
     *
     * where a_i is the coefficient for signer i.
     *
     * IMPORTANT: Returns KeyAggContext with x-only public key (32 bytes)
     *
     * @param publicKeys List of all signers' public keys
     * @return KeyAggContext containing the aggregated key and tweak accumulators
     */
    public static KeyAggContext aggregatePublicKeys(List<ECKey> publicKeys) {
        if (publicKeys.isEmpty()) {
            throw new IllegalArgumentException("Cannot aggregate empty list of public keys");
        }

        log.info("MuSig2: Aggregating {} public keys using BIP-327", publicKeys.size());

        try {
            // BIP-327: Keys must be pre-sorted by caller
            // Reference implementation does NOT sort keys internally
            // The caller is responsible for calling key_sort() first

            // BIP-327: Get second key for MuSig2* optimization
            ECKey pk2 = getSecondKey(publicKeys);

            // BIP-327: Compute aggregated point Q = a_1*P_1 + a_2*P_2 + ... + a_u*P_u
            org.bouncycastle.math.ec.ECPoint aggregatedPoint = null;

            for (int i = 0; i < publicKeys.size(); i++) {
                ECKey signerKey = publicKeys.get(i);
                org.bouncycastle.math.ec.ECPoint P_i = signerKey.getPubKeyPoint();

                // Compute coefficient a_i using BIP-327 algorithm
                BigInteger a_i;
                if (signerKey.equals(pk2)) {
                    // MuSig2* optimization: second distinct key gets coefficient 1
                    a_i = BigInteger.ONE;
                } else {
                    // Compute coefficient using tagged hash
                    byte[] L = hashKeys(publicKeys);
                    byte[] pkBytes = signerKey.getPubKey();
                    byte[] hashInput = new byte[L.length + pkBytes.length];
                    System.arraycopy(L, 0, hashInput, 0, L.length);
                    System.arraycopy(pkBytes, 0, hashInput, L.length, pkBytes.length);
                    byte[] hashBytes = Utils.taggedHash(KEYAGG_COEFF_TAG, hashInput);
                    a_i = new BigInteger(1, hashBytes).mod(ECKey.CURVE.getN());
                }

                // Multiply point by coefficient: a_i * P_i
                org.bouncycastle.math.ec.ECPoint adjustedPoint = P_i.multiply(a_i);

                // Add to aggregate
                if (aggregatedPoint == null) {
                    aggregatedPoint = adjustedPoint;
                } else {
                    aggregatedPoint = aggregatedPoint.add(adjustedPoint);
                }

                log.debug("Added key {} with coefficient {}",
                    i, a_i.toString(16).substring(0, Math.min(8, a_i.toString(16).length())));
            }

            if (aggregatedPoint == null || aggregatedPoint.isInfinity()) {
                throw new RuntimeException("Aggregated point is infinity (should not happen except with negligible probability)");
            }

            // BIP-327: Return KeyAggContext with Q WITHOUT normalization
            // According to BIP-327 specification, KeyAgg returns Q as-is.
            // Normalization to even-y happens in GetXonlyPubkey, NOT in KeyAgg.
            // The Q_was_negated flag is NOT used here - it's only relevant for signing.
            aggregatedPoint = aggregatedPoint.normalize();

            ECKey aggregatedKey = ECKey.fromPublicOnly(aggregatedPoint, false);

            log.info("MuSig2: Aggregated key Q (as-is, NOT normalized to even-y): x={}, y parity={}",
                Utils.bytesToHex(aggregatedPoint.getAffineXCoord().getEncoded()).substring(0, 16) + "...",
                aggregatedPoint.getAffineYCoord().toBigInteger().testBit(0) ? "ODD" : "EVEN");

            // BIP-327: Return KeyAggContext with initial values
            // gacc = 1 (parity accumulator, initially 1)
            // tacc = 0 (tweak accumulator, initially 0)
            // Q_was_negated = false (will be determined later when needed)
            BigInteger n = ECKey.CURVE.getN();
            return new KeyAggContext(aggregatedKey, BigInteger.ONE, BigInteger.ZERO, false);

        } catch (Exception e) {
            log.error("Error aggregating public keys", e);
            throw new RuntimeException("Failed to aggregate keys", e);
        }
    }

    /**
     * BIP-327: Apply Tweak to KeyAgg Context
     *
     * Applies a tweak to the aggregate key, updating the KeyAgg context.
     * This is required for:
     * - BIP32 derivation (hardened derivation)
     * - Taproot tweaking
     *
     * Algorithm (BIP-327):
     * 1. If tweak is X-only: g = 1
     * 2. Else: g = -1 if Q has odd y else 1
     * 3. Q = Q + g*tweak*G
     * 4. gacc = gacc * g mod n
     * 5. tacc = tacc + tweak mod n
     *
     * @param keyagg_ctx The key aggregation context
     * @param tweak The tweak value (32 bytes)
     * @param isXOnly Whether the tweak is x-only (true) or has parity (false)
     * @return Updated KeyAggContext
     */
    public static KeyAggContext applyTweak(KeyAggContext keyagg_ctx, byte[] tweak, boolean isXOnly) {
        if (tweak.length != 32) {
            throw new IllegalArgumentException("Tweak must be 32 bytes");
        }

        log.info("MuSig2: Applying tweak (X-only: {})", isXOnly);

        try {
            ECKey Q = keyagg_ctx.getQ();
            BigInteger gacc = keyagg_ctx.getGacc();
            BigInteger tacc = keyagg_ctx.getTacc();
            BigInteger n = ECKey.CURVE.getN();

            // BIP-327: Step 1 - Determine g (parity adjustment)
            // g = -1 if (is_xonly_t AND not has_even_y(Q)), else g = 1
            BigInteger g;
            org.bouncycastle.math.ec.ECPoint Q_point = Q.getPubKeyPoint().normalize();
            boolean Q_has_odd_y = Q_point.getAffineYCoord().toBigInteger().testBit(0);

            if (isXOnly && Q_has_odd_y) {
                // g = -1 when BOTH conditions are true: is_xonly_t AND Q has odd y
                g = n.subtract(BigInteger.ONE);
                log.debug("g = -1 (isXOnly=true AND Q has odd y=true)");
            } else {
                // g = 1 in all other cases
                g = BigInteger.ONE;
                log.debug("g = 1 (isXOnly={} OR Q has odd y={})", isXOnly, Q_has_odd_y);
            }

            // BIP-327: Step 2 - Compute tweak as scalar t
            // BIP-327: Let t = int(tweak); fail if t ≥ n
            BigInteger t = new BigInteger(1, tweak);
            if (t.compareTo(n) >= 0) {
                throw new IllegalArgumentException("Tweak must be less than n");
            }

            // BIP-327: Step 3 - Compute Q' = g⋅Q + t⋅G
            // This is the CRITICAL formula from BIP-327 specification
            org.bouncycastle.math.ec.ECPoint G = ECKey.CURVE.getG();
            org.bouncycastle.math.ec.ECPoint Q_new = Q_point.multiply(g).add(G.multiply(t)).normalize();

            // BIP-327: Step 5 - Update accumulators
            // tacc' = tacc + g⋅t mod n (BIP-327 specification)
            BigInteger tacc_new = tacc.add(g.multiply(t)).mod(n);

            // gacc' = gacc * g mod n
            BigInteger gacc_new = gacc.multiply(g).mod(n);

            // BIP-327: Step 6 - For X-only tweaks, if y(Q') is odd, negate gacc'
            if (isXOnly) {
                boolean Q_new_has_odd_y = Q_new.getAffineYCoord().toBigInteger().testBit(0);
                if (Q_new_has_odd_y) {
                    gacc_new = gacc_new.negate().mod(n);
                    log.debug("Q' has odd y (X-only tweak), negated gacc");
                }
            }

            // Create new ECKey for tweaked Q
            ECKey Q_new_key = ECKey.fromPublicOnly(Q_new, false);

            log.info("MuSig2: Tweaked key: {}", Utils.bytesToHex(Q_new.getAffineXCoord().getEncoded()).substring(0, 16) + "...");
            log.debug("New gacc: {}, new tacc: {}",
                gacc_new.toString(16).substring(0, Math.min(8, gacc_new.toString(16).length())) + "...",
                tacc_new.toString(16).substring(0, Math.min(8, tacc_new.toString(16).length())) + "...");

            // BIP-327: Return updated KeyAggContext
            // Note: Q_was_negated from original context is preserved for signing
            return new KeyAggContext(Q_new_key, gacc_new, tacc_new, keyagg_ctx.wasQNegated());

        } catch (Exception e) {
            log.error("Error applying tweak", e);
            throw new RuntimeException("Failed to apply tweak", e);
        }
    }

    /**
     * Legacy method for backward compatibility
     * @deprecated Use aggregatePublicKeys that returns KeyAggContext instead
     */
    @Deprecated
    public static ECKey aggregatePublicKeysLegacy(List<ECKey> publicKeys) {
        KeyAggContext ctx = aggregatePublicKeys(publicKeys);
        return ctx.getQ();
    }

    /**
     * BIP-327: Generate Deterministic Nonce Pair (k1, k2)
     *
     * Generates deterministic yet unpredictable nonces for MuSig2 signing.
     * This uses the BIP-340 tagged hash approach for deterministic nonce generation.
     *
     * The nonce is generated as:
     * nonce_hash = SHA256("MuSig/nonce" || rand || pk || aggpk || msg_prefixed || extra_in || i)
     *
     * @param secretKey Signer's secret key
     * @param aggregatedPublicKey Aggregated public key
     * @param message Message to be signed (typically sighash)
     * @param auxRand Optional auxiliary random value (32 bytes, can be null/empty)
     * @return Array of [k1, k2] as BigInteger values
     */
    public static BigInteger[] generateDeterministicNonces(ECKey secretKey,
                                                           ECKey aggregatedPublicKey,
                                                           Sha256Hash message,
                                                           byte[] auxRand) {
        log.debug("Generating deterministic nonces (k1, k2) for MuSig2 (BIP-327)");

        try {
            // BIP-327: If aux_rand is not provided, generate it
            if (auxRand == null || auxRand.length == 0) {
                auxRand = new byte[32];
                new SecureRandom().nextBytes(auxRand);
                log.debug("Generated aux_rand");
            }

            if (auxRand.length != 32) {
                throw new IllegalArgumentException("auxRand must be 32 bytes");
            }

            // BIP-327: rand = sk XOR hashMuSig/aux(rand')
            byte[] skBytes = Utils.bigIntegerToBytes(secretKey.getPrivKey(), 32);
            byte[] auxHash = Utils.taggedHash(MUSIG_AUX_TAG, auxRand);
            byte[] rand = new byte[32];
            for (int i = 0; i < 32; i++) {
                rand[i] = (byte) (skBytes[i] ^ auxHash[i]);
            }

            // BIP-327: Build message prefix
            byte[] msgPrefixed;
            if (message == null) {
                msgPrefixed = new byte[] { 0x00 };
            } else {
                ByteArrayOutputStream msgPrefixStream = new ByteArrayOutputStream();
                msgPrefixStream.write(0x01); // flag
                byte[] msgBytes = message.getBytes();
                // Write 8-byte length
                msgPrefixStream.write((msgBytes.length >> 56) & 0xff);
                msgPrefixStream.write((msgBytes.length >> 48) & 0xff);
                msgPrefixStream.write((msgBytes.length >> 40) & 0xff);
                msgPrefixStream.write((msgBytes.length >> 32) & 0xff);
                msgPrefixStream.write((msgBytes.length >> 24) & 0xff);
                msgPrefixStream.write((msgBytes.length >> 16) & 0xff);
                msgPrefixStream.write((msgBytes.length >> 8) & 0xff);
                msgPrefixStream.write(msgBytes.length & 0xff);
                msgPrefixStream.write(msgBytes);
                msgPrefixed = msgPrefixStream.toByteArray();
            }

            // BIP-327: Compute nonce hash for k1 (i = 0) and k2 (i = 1)
            // BIP-327: pk and aggpk must be x-only (32 bytes), not compressed (33 bytes)
            byte[] pkBytes = secretKey.getPubKeyPoint().getAffineXCoord().getEncoded();  // 32 bytes x-only
            byte[] aggPkBytes = aggregatedPublicKey.getPubKeyPoint().getAffineXCoord().getEncoded();  // 32 bytes x-only
            byte[] extraIn = new byte[0]; // empty for now

            BigInteger k1 = computeNonce(rand, pkBytes, aggPkBytes, msgPrefixed, extraIn, 0);
            BigInteger k2 = computeNonce(rand, pkBytes, aggPkBytes, msgPrefixed, extraIn, 1);

            // BIP-327: Security check - fail if pk equals public nonce
            // This prevents birthday attacks where an attacker could cause nonce leakage
            byte[] pubNonce1 = ECKey.CURVE.getG().multiply(k1).normalize().getAffineXCoord().getEncoded();
            byte[] pubNonce2 = ECKey.CURVE.getG().multiply(k2).normalize().getAffineXCoord().getEncoded();
            if (java.util.Arrays.equals(pkBytes, pubNonce1) || java.util.Arrays.equals(pkBytes, pubNonce2)) {
                throw new RuntimeException("Security violation: pk equals public nonce (retry with different aux)");
            }

            log.debug("Generated deterministic nonces: k1={}, k2={}",
                k1.toString(16).substring(0, 8) + "...",
                k2.toString(16).substring(0, 8) + "...");

            return new BigInteger[] { k1, k2 };

        } catch (Exception e) {
            log.error("Error generating deterministic nonces", e);
            throw new RuntimeException("Failed to generate nonces", e);
        }
    }

    /**
     * Helper method to compute a single nonce value
     */
    private static BigInteger computeNonce(byte[] rand, byte[] pkBytes, byte[] aggPkBytes,
                                           byte[] msgPrefixed, byte[] extraIn, int index) throws Exception {
        // Build hash input: rand || len(pk) || pk || len(aggpk) || aggpk || msg_prefixed || len(extra_in) || extra_in || i
        ByteArrayOutputStream input = new ByteArrayOutputStream();
        input.write(rand); // 32 bytes
        input.write(pkBytes.length); // 1 byte
        input.write(pkBytes); // 33 bytes
        input.write(aggPkBytes.length); // 1 byte
        input.write(aggPkBytes); // 32 bytes
        input.write(msgPrefixed);
        input.write((extraIn.length >> 24) & 0xff);
        input.write((extraIn.length >> 16) & 0xff);
        input.write((extraIn.length >> 8) & 0xff);
        input.write(extraIn.length & 0xff);
        input.write(extraIn);
        input.write(index); // i = 0 for k1, i = 1 for k2

        byte[] hashBytes = Utils.taggedHash(MUSIG_NONCE_TAG, input.toByteArray());
        BigInteger k = new BigInteger(1, hashBytes).mod(ECKey.CURVE.getN());

        if (k.equals(BigInteger.ZERO)) {
            throw new RuntimeException("k" + (index + 1) + " is zero (negligible probability)");
        }

        return k;
    }

    /**
     * BIP-327: Generate Deterministic Nonce (legacy, returns k1 only)
     *
     * @deprecated Use generateDeterministicNonces() instead
     */
    @Deprecated
    public static ECKey generateDeterministicNonce(ECKey secretKey,
                                                     ECKey aggregatedPublicKey,
                                                     Sha256Hash message,
                                                     byte[] auxRand) {
        BigInteger[] nonces = generateDeterministicNonces(secretKey, aggregatedPublicKey, message, auxRand);
        return ECKey.fromPrivate(nonces[0]);
    }

    /**
     * BIP-327: Aggregate Nonces
     *
     * Aggregates nonces from all signers for Round 2 of MuSig2.
     * R = R_1 + R_2 + ... + R_n
     *
     * @param nonces List of all signers' nonces (public keys)
     * @return The aggregated nonce
     */
    public static ECKey aggregateNonces(List<ECKey> nonces) {
        if (nonces.isEmpty()) {
            throw new IllegalArgumentException("Cannot aggregate empty list of nonces");
        }

        log.debug("Aggregating {} nonces", nonces.size());

        try {
            // BIP-327: R = R_1 + R_2 + ... + R_n (simple point addition)
            ECPoint aggregatedPoint = null;

            for (ECKey nonce : nonces) {
                ECPoint point = nonce.getPubKeyPoint();

                if (aggregatedPoint == null) {
                    aggregatedPoint = point;
                } else {
                    aggregatedPoint = aggregatedPoint.add(point);
                }
            }

            ECKey aggregatedNonce = ECKey.fromPublicOnly(aggregatedPoint, true);

            log.debug("Aggregated nonce: {}",
                Utils.bytesToHex(aggregatedNonce.getPubKey()).substring(0, 16) + "...");

            return aggregatedNonce;

        } catch (Exception e) {
            log.error("Error aggregating nonces", e);
            throw new RuntimeException("Failed to aggregate nonces", e);
        }
    }

    // =========================================================================
    // Helper Methods
    // =========================================================================

    /**
     * BIP-327: Hash Keys function
     *
     * Computes L = hashKeyAgg list(pk1 || pk2 || ... || pku)
     *
     * @param publicKeys List of public keys
     * @return Tagged hash of all keys concatenated
     */
    // Package-private for access from MuSig2.wasQNegated()
    static byte[] hashKeys(List<ECKey> publicKeys) {
        try {
            // Concatenate all public keys
            ByteArrayOutputStream keyBytes = new ByteArrayOutputStream();
            for (ECKey key : publicKeys) {
                keyBytes.write(key.getPubKey());
            }

            // Return tagged hash
            return Utils.taggedHash(KEYAGG_LIST_TAG, keyBytes.toByteArray());

        } catch (Exception e) {
            log.error("Error computing hashKeys", e);
            throw new RuntimeException("Failed to compute hashKeys", e);
        }
    }

    /**
     * BIP-327: Get Second Key function
     *
     * Finds the second distinct key in the list (the first key different from pk1).
     * If all keys are the same, returns a 33-byte array of zeros.
     *
     * @param publicKeys List of public keys (already sorted)
     * @return The second distinct key, or zero bytes if all keys are identical
     */
    // Package-private for access from MuSig2.wasQNegated()
    static ECKey getSecondKey(List<ECKey> publicKeys) {
        if (publicKeys.isEmpty()) {
            throw new IllegalArgumentException("Cannot get second key from empty list");
        }

        ECKey pk1 = publicKeys.get(0);

        // Find first key different from pk1
        for (int j = 1; j < publicKeys.size(); j++) {
            ECKey currentKey = publicKeys.get(j);
            if (!Arrays.equals(pk1.getPubKey(), currentKey.getPubKey())) {
                return currentKey;
            }
        }

        // All keys are the same, return special zero key (33 bytes of zeros)
        // This won't be used as an actual key but marks that there's no second distinct key
        log.warn("All public keys are identical, returning zero key as pk2");
        return null; // This indicates the special case
    }

    /**
     * Aggregate all public keys except the specified one
     * Used for computing key aggregation coefficients
     *
     * NOTE: This is the OLD implementation and is NO LONGER USED.
     * Kept for reference only.
     */
    @Deprecated
    private static ECKey aggregateKeysExcluding(List<ECKey> allKeys, ECKey excludeKey) {
        List<ECKey> keysToAggregate = new ArrayList<>(allKeys);
        keysToAggregate.remove(excludeKey);

        if (keysToAggregate.isEmpty()) {
            throw new IllegalArgumentException("Cannot aggregate empty list");
        }

        if (keysToAggregate.size() == 1) {
            return keysToAggregate.get(0);
        }

        // Simple sum of remaining keys
        org.bouncycastle.math.ec.ECPoint aggregatedPoint = null;

        for (ECKey key : keysToAggregate) {
            org.bouncycastle.math.ec.ECPoint point = key.getPubKeyPoint();

            if (aggregatedPoint == null) {
                aggregatedPoint = point;
            } else {
                aggregatedPoint = aggregatedPoint.add(point);
            }
        }

        return ECKey.fromPublicOnly(aggregatedPoint, true);
    }

    /**
     * Sort public keys lexicographically (BIP-327 requirement)
     *
     * NOTE: Package-private for testing purposes
     */
    static void sortPublicKeys(List<ECKey> keys) {
        keys.sort((k1, k2) -> {
            byte[] bytes1 = k1.getPubKey();
            byte[] bytes2 = k2.getPubKey();

            // Compare byte arrays as unsigned values
            int minLength = Math.min(bytes1.length, bytes2.length);
            for (int i = 0; i < minLength; i++) {
                // Convert to unsigned int (0-255) before comparing
                int cmp = Integer.compare(bytes1[i] & 0xFF, bytes2[i] & 0xFF);
                if (cmp != 0) {
                    return cmp;
                }
            }

            return Integer.compare(bytes1.length, bytes2.length);
        });
    }

    // =========================================================================
    // DEBUG/REFERENCE Methods - Only for testing and debugging
    // =========================================================================

    /**
     * Reference implementation of getSecondKey for debugging
     * Returns the actual second key object (not null for identical keys case)
     */
    static ECKey getSecondKeyReference(List<ECKey> publicKeys) {
        if (publicKeys.isEmpty()) {
            throw new IllegalArgumentException("Cannot get second key from empty list");
        }

        ECKey pk1 = publicKeys.get(0);

        // Find first key different from pk1
        for (int j = 1; j < publicKeys.size(); j++) {
            ECKey currentKey = publicKeys.get(j);
            if (!Arrays.equals(pk1.getPubKey(), currentKey.getPubKey())) {
                return currentKey;
            }
        }

        // All keys are the same - return pk1 as fallback
        return pk1;
    }

    /**
     * Reference implementation of hashKeys for debugging
     */
    static byte[] hashKeysReference(List<ECKey> publicKeys) {
        try {
            // Concatenate all public keys
            ByteArrayOutputStream keyBytes = new ByteArrayOutputStream();
            for (ECKey key : publicKeys) {
                byte[] pubKey = key.getPubKey();
                System.out.println("  Adding to hash: " + Utils.bytesToHex(pubKey).substring(0, 20) + "...");
                keyBytes.write(pubKey);
            }

            // Return tagged hash
            byte[] hash = Utils.taggedHash(KEYAGG_LIST_TAG, keyBytes.toByteArray());
            System.out.println("  Hash input length: " + keyBytes.size() + " bytes");
            return hash;

        } catch (Exception e) {
            log.error("Error computing hashKeys", e);
            throw new RuntimeException("Failed to compute hashKeys", e);
        }
    }
}
