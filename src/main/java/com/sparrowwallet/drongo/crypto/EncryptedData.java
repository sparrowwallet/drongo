package com.sparrowwallet.drongo.crypto;

import java.util.Arrays;
import java.util.Objects;

/**
 * <p>An instance of EncryptedData is a holder for an initialization vector and encrypted bytes. It is typically
 * used to hold encrypted private key bytes.</p>
 *
 * <p>The initialisation vector is random data that is used to initialise the AES block cipher when the
 * private key bytes were encrypted. You need these for decryption.</p>
 */
public final class EncryptedData {
    private final byte[] initialisationVector;
    private final byte[] encryptedBytes;
    private final byte[] keySalt;

    public EncryptedData(byte[] initialisationVector, byte[] encryptedBytes, byte[] keySalt) {
        this.initialisationVector = Arrays.copyOf(initialisationVector, initialisationVector.length);
        this.encryptedBytes = Arrays.copyOf(encryptedBytes, encryptedBytes.length);
        this.keySalt = keySalt == null ? null : Arrays.copyOf(keySalt, keySalt.length);
    }

    public byte[] getInitialisationVector() {
        return initialisationVector;
    }

    public byte[] getEncryptedBytes() {
        return encryptedBytes;
    }

    public byte[] getKeySalt() {
        return keySalt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EncryptedData other = (EncryptedData) o;
        return Arrays.equals(encryptedBytes, other.encryptedBytes) && Arrays.equals(initialisationVector, other.initialisationVector) && Arrays.equals(keySalt, other.keySalt);
    }

    @Override
    public int hashCode() {
        return Objects.hash(Arrays.hashCode(encryptedBytes), Arrays.hashCode(initialisationVector), Arrays.hashCode(keySalt));
    }

    @Override
    public String toString() {
        return "EncryptedData [initialisationVector=" + Arrays.toString(initialisationVector)
                + ", encryptedPrivateKey=" + Arrays.toString(encryptedBytes)
                + ", keySalt=" + Arrays.toString(keySalt) + "]";
    }

    public EncryptedData copy() {
        return new EncryptedData(Arrays.copyOf(initialisationVector, initialisationVector.length),
                Arrays.copyOf(encryptedBytes, encryptedBytes.length),
                Arrays.copyOf(keySalt, keySalt.length));
    }
}
