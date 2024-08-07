package com.sparrowwallet.drongo.wallet.slip39;

import java.util.ArrayList;
import java.util.List;

import static com.sparrowwallet.drongo.wallet.slip39.Share.CHECKSUM_LENGTH_WORDS;

public class Rs1024 {
    private static final int[] GEN = {
            0xE0E040,
            0x1C1C080,
            0x3838100,
            0x7070200,
            0xE0E0009,
            0x1C0C2412,
            0x38086C24,
            0x3090FC48,
            0x21B1F890,
            0x3F3F120
    };

    private static int polymod(List<Integer> values) {
        int chk = 1;
        for(int v : values) {
            int b = chk >> 20;
            chk = (chk & 0xFFFFF) << 10 ^ v;
            for(int i = 0; i < 10; i++) {
                if(((b >> i) & 1) != 0) {
                    chk ^= GEN[i];
                }
            }
        }
        return chk;
    }

    public static List<Integer> createChecksum(List<Integer> data, byte[] customizationString) {
        List<Integer> values = new ArrayList<>();
        for(byte b : customizationString) {
            values.add((int) b & 0xFF);
        }
        values.addAll(data);
        for(int i = 0; i < CHECKSUM_LENGTH_WORDS; i++) {
            values.add(0);
        }

        int polymod = polymod(values) ^ 1;
        List<Integer> checksum = new ArrayList<>(CHECKSUM_LENGTH_WORDS);
        for(int i = CHECKSUM_LENGTH_WORDS - 1; i >= 0; i--) {
            checksum.add((polymod >> (10 * i)) & 1023);
        }
        return checksum;
    }

    public static boolean verifyChecksum(List<Integer> data, byte[] customizationString) {
        List<Integer> values = new ArrayList<>();
        for(byte b : customizationString) {
            values.add((int) b & 0xFF);
        }
        values.addAll(data);

        return polymod(values) == 1;
    }
}
