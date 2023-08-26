package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.Utils;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class SeedQR {
    public static DeterministicSeed getSeed(String seedQr) {
        if(seedQr.length() < 48 || seedQr.length() > 96 || seedQr.length() % 4 > 0) {
            throw new IllegalArgumentException("Invalid SeedQR length: " + seedQr.length());
        }

        if(!seedQr.chars().allMatch(c -> c >= '0' && c <= '9')) {
            throw new IllegalArgumentException("SeedQR contains non-digit characters: " + seedQr);
        }

        List<Integer> indexes = IntStream.iterate(0, i -> i + 4).limit((int)Math.ceil(seedQr.length() / 4.0))
                .mapToObj(i -> seedQr.substring(i, Math.min(i + 4, seedQr.length())))
                .map(Integer::parseInt)
                .collect(Collectors.toList());

        List<String> words = new ArrayList<>(indexes.size());
        for(Integer index : indexes) {
            words.add(Bip39MnemonicCode.INSTANCE.getWordList().get(index));
        }

        return new DeterministicSeed(words, null, System.currentTimeMillis(), DeterministicSeed.Type.BIP39);
    }

    public static DeterministicSeed getSeed(byte[] compactSeedQr) {
        byte[] seed;

        if(compactSeedQr.length == 16 || compactSeedQr.length == 32) {
            //Assume scan contains seed only
            seed = compactSeedQr;
        } else {
            //Assume scan contains header, seed and EC bytes
            if(compactSeedQr[0] != 0x41 && compactSeedQr[0] != 0x42) {
                throw new IllegalArgumentException("Invalid CompactSeedQR header");
            }

            if(compactSeedQr.length < 19) {
                throw new IllegalArgumentException("Invalid CompactSeedQR length");
            }

            String qrHex = Utils.bytesToHex(compactSeedQr);
            String seedHex;
            if(qrHex.endsWith("0ec11ec11")) {
                seedHex = qrHex.substring(3, qrHex.length() - 9); //12 word, high EC
            } else if(qrHex.endsWith("0ec")) {
                seedHex = qrHex.substring(3, qrHex.length() - 3); //12 word, low EC
            } else {
                seedHex = qrHex.substring(3, qrHex.length() - 1); //24 word
            }

            seed = Utils.hexToBytes(seedHex);
        }

        if(seed.length < 16 || seed.length > 32 || seed.length % 4 > 0) {
            throw new IllegalArgumentException("Invalid CompactSeedQR length: " + compactSeedQr.length);
        }

        return new DeterministicSeed(seed, null, System.currentTimeMillis());
    }
}
