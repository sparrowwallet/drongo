package com.sparrowwallet.drongo.crypto.musig2;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

/**
 * BIP-327 MuSig2 Utility Methods
 *
 * Contains shared utility methods used across MuSig2 implementation.
 * These methods implement common BIP-327 operations that are needed
 * in multiple places to avoid code duplication.
 *
 * BIP-327 Reference: https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki
 *
 * @author Claude (AI Assistant)
 * @version 0.1.0 (Refactoring)
 * @since 2025-12-31
 */
public class MuSig2Utils {

    /**
     * BIP-327: Check if an elliptic curve point has an even y-coordinate.
     *
     * In BIP-340/341, the parity of the y-coordinate determines which
     * of the two points with a given x-coordinate is selected.
     *
     * @param point The elliptic curve point (normalized)
     * @return true if y-coordinate is even, false if odd
     * @throws IllegalArgumentException if point is null
     */
    public static boolean hasEvenY(ECPoint point) {
        if (point == null) {
            throw new IllegalArgumentException("ECPoint cannot be null");
        }
        // BIP-340: y is even if the least significant bit is 0
        return !point.getAffineYCoord().toBigInteger().testBit(0);
    }

    /**
     * BIP-327: Get x-only public key (32 bytes) with even y-coordinate.
     *
     * This implements the with_even_y(P) function from BIP-327:
     * - If P has even y, return x(P)
     * - If P has odd y, return x(-P) where -P has even y
     *
     * This is used throughout BIP-327 for:
     * - Public key encoding
     * - Challenge computation
     * - Signature verification
     *
     * @param point The elliptic curve point (must be normalized)
     * @return 32-byte x-coordinate (with even y)
     * @throws IllegalArgumentException if point is null
     */
    public static byte[] getXonlyPubkey(ECPoint point) {
        if (point == null) {
            throw new IllegalArgumentException("ECPoint cannot be null");
        }

        ECPoint normalized = point.normalize();

        // BIP-327: with_even_y(P) - if P has odd y, negate it
        if (hasEvenY(normalized)) {
            // y is even - return x-coordinate directly
            return normalized.getAffineXCoord().getEncoded();
        } else {
            // y is odd - negate to get point with even y, then return x-coordinate
            ECPoint evenPoint = normalized.negate().normalize();
            return evenPoint.getAffineXCoord().getEncoded();
        }
    }

    /**
     * BIP-327: Get point with even y-coordinate (with_even_y function).
     *
     * Returns the point itself if it has even y, otherwise returns the negated point.
     * This is useful when you need the actual ECPoint object, not just the x-coordinate.
     *
     * @param point The elliptic curve point (must be normalized)
     * @return Point guaranteed to have even y-coordinate
     * @throws IllegalArgumentException if point is null
     */
    public static ECPoint withEvenY(ECPoint point) {
        if (point == null) {
            throw new IllegalArgumentException("ECPoint cannot be null");
        }

        ECPoint normalized = point.normalize();

        // BIP-327: with_even_y(P)
        if (hasEvenY(normalized)) {
            // y is even - return point as-is
            return normalized;
        } else {
            // y is odd - return negated point (which has even y)
            return normalized.negate().normalize();
        }
    }

    /**
     * Encode an EC point as a compressed public key (33 bytes).
     *
     * Compressed encoding: [0x02 or 0x03][x-coordinate]
     * - 0x02 if y is even
     * - 0x03 if y is odd
     *
     * @param point The elliptic curve point (must be normalized)
     * @return 33-byte compressed public key
     * @throws IllegalArgumentException if point is null
     */
    public static byte[] encodeCompressedPoint(ECPoint point) {
        if (point == null) {
            throw new IllegalArgumentException("ECPoint cannot be null");
        }

        byte[] xBytes = point.getAffineXCoord().getEncoded();
        byte yParity = point.getAffineYCoord().toBigInteger().mod(BigInteger.TWO).byteValue();

        byte[] encoded = new byte[33];
        encoded[0] = (yParity == 0) ? (byte) 0x02 : (byte) 0x03;
        System.arraycopy(xBytes, 0, encoded, 1, 32);

        return encoded;
    }

    /**
     * Compute the parity adjustment factor for a point.
     *
     * Returns 1 if the point has even y, -1 mod n if odd y.
     * This is used in signing and verification computations.
     *
     * @param point The elliptic curve point (must be normalized)
     * @param n The curve order
     * @return 1 if even y, n-1 if odd y
     * @throws IllegalArgumentException if point is null
     */
    public static BigInteger parityFactor(ECPoint point, BigInteger n) {
        if (point == null) {
            throw new IllegalArgumentException("ECPoint cannot be null");
        }

        if (hasEvenY(point)) {
            return BigInteger.ONE;
        } else {
            return n.subtract(BigInteger.ONE);  // -1 mod n
        }
    }

    // Private constructor to prevent instantiation
    private MuSig2Utils() {
        throw new UnsupportedOperationException("Utility class cannot be instantiated");
    }
}
