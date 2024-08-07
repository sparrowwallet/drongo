package com.sparrowwallet.drongo.wallet.slip39;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Utils {
    public static final int RADIX_BITS = 10;

    public static int roundBits(int n, int radixBits) {
        // Get the number of `radixBits`-sized digits required to store a `n`-bit value.
        return (n + radixBits - 1) / radixBits;
    }

    public static int bitsToBytes(int n) {
        // Round up bit count to whole bytes.
        return roundBits(n, 8);
    }

    public static int bitsToWords(int n) {
        // Round up bit count to a multiple of word size.
        return roundBits(n, RADIX_BITS);
    }

    public static List<Integer> intToIndices(BigInteger value, int length, int radixBits) {
        // Convert an integer value to indices in big endian order.
        BigInteger mask = BigInteger.ONE.shiftLeft(radixBits).subtract(BigInteger.ONE);
        List<Integer> indices = new ArrayList<>(length);
        for(int i = length - 1; i >= 0; i--) {
            indices.add((value.shiftRight(i * radixBits)).and(mask).intValue());
        }
        return indices;
    }

    public static byte[] concatenate(byte[]... arrays) {
        int totalLength = Arrays.stream(arrays).mapToInt(a -> a.length).sum();
        byte[] result = new byte[totalLength];
        int offset = 0;
        for(byte[] array : arrays) {
            System.arraycopy(array, 0, result, offset, array.length);
            offset += array.length;
        }
        return result;
    }

    public static int byteArrayToInt(byte[] bytes) {
        int value = 0;
        for(byte b : bytes) {
            value = (value << 8) | (b & 0xFF);
        }
        return value;
    }
}
