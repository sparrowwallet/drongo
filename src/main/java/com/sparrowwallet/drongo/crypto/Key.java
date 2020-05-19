package com.sparrowwallet.drongo.crypto;

import java.util.Arrays;

public class Key {
    private final byte[] keyBytes;
    private final byte[] salt;
    private final EncryptionType.Deriver deriver;

    public Key(byte[] keyBytes, byte[] salt, EncryptionType.Deriver deriver) {
        this.keyBytes = keyBytes;
        this.salt = salt;
        this.deriver = deriver;
    }

    public byte[] getKeyBytes() {
        return keyBytes;
    }

    public byte[] getSalt() {
        return salt;
    }

    public EncryptionType.Deriver getDeriver() {
        return deriver;
    }

    public void clear() {
        Arrays.fill(keyBytes, (byte)0);
    }
}
