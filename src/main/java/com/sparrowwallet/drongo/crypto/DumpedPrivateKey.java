package com.sparrowwallet.drongo.crypto;


import com.sparrowwallet.drongo.Network;

import java.util.Arrays;
import java.util.Objects;

/**
 * Parses and generates private keys in the form used by the Bitcoin "dumpprivkey" command. This is the private key
 * bytes with a header byte and 4 checksum bytes at the end. If there are 33 private key bytes instead of 32, then
 * the last byte is a discriminator value for the compressed pubkey.
 */
public class DumpedPrivateKey extends VersionedChecksummedBytes {
    private static final int PRIVATE_KEY_LENGTH = 32;

    private final boolean compressed;

    /**
     * Construct a private key from its Base58 representation.
     *
     * @param base58 The textual form of the private key.
     */
    public static DumpedPrivateKey fromBase58(String base58) {
        return new DumpedPrivateKey(base58);
    }

    // Used by ECKey.getPrivateKeyEncoded()
    DumpedPrivateKey(byte[] keyBytes, boolean compressed) {
        super(Network.get().getDumpedPrivateKeyHeader(), encode(keyBytes, compressed));
        this.compressed = compressed;
    }

    private static byte[] encode(byte[] keyBytes, boolean compressed) {
        if(keyBytes.length != PRIVATE_KEY_LENGTH) {
            throw new IllegalArgumentException("Private keys must be " + PRIVATE_KEY_LENGTH + " bytes");
        }

        if(!compressed) {
            return keyBytes;
        } else {
            // Keys that have compressed public components have an extra 1 byte on the end in dumped form.
            byte[] bytes = new byte[PRIVATE_KEY_LENGTH + 1];
            System.arraycopy(keyBytes, 0, bytes, 0, PRIVATE_KEY_LENGTH);
            bytes[PRIVATE_KEY_LENGTH] = 1;
            return bytes;
        }
    }

    private DumpedPrivateKey(String encoded) {
        super(encoded);
        if(version != Network.get().getDumpedPrivateKeyHeader()) {
            throw new IllegalArgumentException("Invalid version " + version + " for network " + Network.getCanonical());
        }
        if(bytes.length == PRIVATE_KEY_LENGTH + 1 && bytes[PRIVATE_KEY_LENGTH] == 1) {
            compressed = true;
        } else if(bytes.length == PRIVATE_KEY_LENGTH) {
            compressed = false;
        } else {
            throw new IllegalArgumentException("Wrong number of bytes for a private key, not " + PRIVATE_KEY_LENGTH + " or " + (PRIVATE_KEY_LENGTH + 1));
        }
    }

    /**
     * Returns an ECKey created from this encoded private key. Note that bytes retains the dumped form, so the compression
     * marker byte must be dropped before the remainder is read as the private key.
     */
    public ECKey getKey() {
        return ECKey.fromPrivate(Arrays.copyOf(bytes, PRIVATE_KEY_LENGTH), compressed);
    }

    @Override
    public boolean equals(Object o) {
        if(this == o) {
            return true;
        }
        if(o == null || getClass() != o.getClass()) {
            return false;
        }
        if(!super.equals(o)) {
            return false;
        }
        DumpedPrivateKey that = (DumpedPrivateKey)o;
        return compressed == that.compressed;
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), compressed);
    }
}