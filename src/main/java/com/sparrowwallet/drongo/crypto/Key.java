package com.sparrowwallet.drongo.crypto;

public class Key {
    private final byte[] keyBytes;
    private final byte[] salt;

    public Key(byte[] keyBytes, byte[] salt) {
        this.keyBytes = keyBytes;
        this.salt = salt;
    }

    public byte[] getKeyBytes() {
        return keyBytes;
    }

    public byte[] getSalt() {
        return salt;
    }
}
