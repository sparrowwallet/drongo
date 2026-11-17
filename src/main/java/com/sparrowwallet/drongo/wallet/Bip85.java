package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ChildNumber;
import com.sparrowwallet.drongo.crypto.DeterministicKey;
import com.sparrowwallet.drongo.crypto.HDKeyDerivation;
import com.sparrowwallet.drongo.crypto.HDDerivationException;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

public class Bip85 {
    private static final byte[] BIP85_HMAC_KEY = "bip-entropy-from-k".getBytes(StandardCharsets.UTF_8);
    private static final int BIP85_PURPOSE = 83696968;

    public static DeterministicSeed deriveBip39Child(DeterministicKey parentMasterKey, int words, int index, long creationTimeMillis) throws HDDerivationException {
        if(parentMasterKey == null) {
            throw new IllegalArgumentException("Parent master key is required");
        }
        if(words != 12 && words != 15 && words != 18 && words != 21 && words != 24) {
            throw new IllegalArgumentException("BIP39 child mnemonic must be 12, 15, 18, 21, or 24 words");
        }
        if(index < 0) {
            throw new IllegalArgumentException("Child index must be between 0 and " + Integer.MAX_VALUE);
        }

        DeterministicKey derivedKey = parentMasterKey;
        for(ChildNumber childNumber : List.of(
                new ChildNumber(BIP85_PURPOSE, true),
                new ChildNumber(39, true), // BIP-39 application code
                new ChildNumber(0, true), // BIP-39 language code for english.
                new ChildNumber(words, true),
                new ChildNumber(index, true)
        )) {
            derivedKey = HDKeyDerivation.deriveChildKey(derivedKey, childNumber).dropParent();
        }

        byte[] privateKey = derivedKey.getPrivKeyBytes();
        byte[] entropy;
        try {
            entropy = Utils.getHmacSha512Hash(BIP85_HMAC_KEY, privateKey);
        } finally {
            Arrays.fill(privateKey, (byte)0);
        }

        byte[] childEntropy = null;
        try {
            childEntropy = Arrays.copyOf(entropy, words * 4 / 3);
            return new DeterministicSeed(childEntropy, "", creationTimeMillis, DeterministicSeed.Type.BIP39);
        } finally {
            Arrays.fill(entropy, (byte)0);
            if(childEntropy != null) {
                Arrays.fill(childEntropy, (byte)0);
            }
        }
    }

    private Bip85() {
    }
}
