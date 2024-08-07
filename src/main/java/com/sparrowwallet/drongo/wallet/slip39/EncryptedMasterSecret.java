package com.sparrowwallet.drongo.wallet.slip39;

import java.util.Arrays;

public class EncryptedMasterSecret {
    private final int identifier;
    private final boolean extendable;
    private final int iterationExponent;
    private final byte[] ciphertext;

    public EncryptedMasterSecret(int identifier, boolean extendable, int iterationExponent, byte[] ciphertext) {
        this.identifier = identifier;
        this.extendable = extendable;
        this.iterationExponent = iterationExponent;
        this.ciphertext = Arrays.copyOf(ciphertext, ciphertext.length);
    }

    public int getIdentifier() {
        return identifier;
    }

    public boolean isExtendable() {
        return extendable;
    }

    public int getIterationExponent() {
        return iterationExponent;
    }

    public byte[] getCiphertext() {
        return Arrays.copyOf(ciphertext, ciphertext.length);
    }

    public static EncryptedMasterSecret fromMasterSecret(byte[] masterSecret, byte[] passphrase, int identifier, boolean extendable, int iterationExponent) {
        byte[] ciphertext = Cipher.encrypt(masterSecret, passphrase, iterationExponent, identifier, extendable);
        return new EncryptedMasterSecret(identifier, extendable, iterationExponent, ciphertext);
    }

    public byte[] decrypt(byte[] passphrase) {
        return Cipher.decrypt(ciphertext, passphrase, iterationExponent, identifier, extendable);
    }
}
