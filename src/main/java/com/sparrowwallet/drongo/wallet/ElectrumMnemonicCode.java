package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.Pbkdf2KeyDeriver;

import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.List;

public class ElectrumMnemonicCode {
    private static final int PBKDF2_ROUNDS = 2048;

    private final List<String> VALID_PREFIXES = List.of("01", "100", "101");

    public static ElectrumMnemonicCode INSTANCE = new ElectrumMnemonicCode();

    /**
     * Gets the word list this code uses.
     */
    public List<String> getWordList() {
        return Bip39MnemonicCode.INSTANCE.getWordList();
    }

    public static byte[] toSeed(List<String> seedWords, String passphrase) {
        String mnemonicWords = String.join(" ", seedWords);
        return toSeed(mnemonicWords, passphrase);
    }

    public static byte[] toSeed(String mnemonicWords, String passphrase) {
        if(passphrase == null) {
            passphrase = "";
        }

        String mnemonic = Normalizer.normalize(mnemonicWords, Normalizer.Form.NFKD);
        String salt = "electrum" + Normalizer.normalize(passphrase, Normalizer.Form.NFKD);

        Pbkdf2KeyDeriver keyDeriver = new Pbkdf2KeyDeriver(salt.getBytes(StandardCharsets.UTF_8), PBKDF2_ROUNDS);
        return keyDeriver.deriveKey(mnemonic).getKeyBytes();
    }

    /**
     * Check to see if a mnemonic word list is valid.
     */
    public void check(List<String> words) throws MnemonicException {
        String prefix = getPrefix(words);
        if(!VALID_PREFIXES.contains(prefix)) {
            throw new MnemonicException("Invalid prefix " + prefix);
        }
    }

    private String getPrefix(List<String> words) throws MnemonicException {
        String mnemonic = String.join(" ", words);
        mnemonic = Normalizer.normalize(mnemonic, Normalizer.Form.NFKD);
        byte [] hash = Utils.getHmacSha512Hash("Seed version".getBytes(StandardCharsets.UTF_8), mnemonic.getBytes(StandardCharsets.UTF_8));
        String hex = Utils.bytesToHex(hash);
        try {
            int prefixLength = Integer.parseInt(hex.substring(0, 1)) + 2;
            String prefix = hex.substring(0, prefixLength);
            return Integer.toHexString(Integer.parseInt(prefix, 16));
        } catch(NumberFormatException e) {
            throw new MnemonicException("Invalid prefix bytes");
        }
    }
}
