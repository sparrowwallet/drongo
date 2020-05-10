package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.EncryptableItem;
import com.sparrowwallet.drongo.crypto.EncryptedData;
import com.sparrowwallet.drongo.crypto.EncryptionType;
import com.sparrowwallet.drongo.crypto.KeyCrypter;
import org.bouncycastle.crypto.params.KeyParameter;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

public class DeterministicSeed implements EncryptableItem {
    public static final int DEFAULT_SEED_ENTROPY_BITS = 128;
    public static final int MAX_SEED_ENTROPY_BITS = 512;

    private final byte[] seed;
    private final EncryptedData encryptedSeed;
    private long creationTimeSeconds;

    public DeterministicSeed(byte[] seed, long creationTimeSeconds) {
        this.seed = seed;
        this.encryptedSeed = null;
        this.creationTimeSeconds = creationTimeSeconds;
    }

    public DeterministicSeed(EncryptedData encryptedSeed, long creationTimeSeconds) {
        this.seed = null;
        this.encryptedSeed = encryptedSeed;
        this.creationTimeSeconds = creationTimeSeconds;
    }

    /**
     * Constructs a seed from a BIP 39 mnemonic code. See {@link Bip39MnemonicCode} for more
     * details on this scheme.
     * @param random Entropy source
     * @param bits number of bits, must be divisible by 32
     * @param passphrase A user supplied passphrase, or an empty string if there is no passphrase
     */
    public DeterministicSeed(SecureRandom random, int bits, String passphrase) {
        this(getEntropy(random, bits), passphrase, System.currentTimeMillis());
    }

    /**
     * Constructs a seed from a BIP 39 mnemonic code. See {@link Bip39MnemonicCode} for more
     * details on this scheme.
     * @param entropy entropy bits, length must be divisible by 32
     * @param passphrase A user supplied passphrase, or an empty string if there is no passphrase
     * @param creationTimeSeconds When the seed was originally created, UNIX time.
     */
    public DeterministicSeed(byte[] entropy, String passphrase, long creationTimeSeconds) {
        if(entropy.length % 4 != 0) {
            throw new IllegalArgumentException("Entropy size in bits not divisible by 32");
        }

        if(entropy.length * 8 < DEFAULT_SEED_ENTROPY_BITS) {
            throw new IllegalArgumentException("Entropy size too small");
        }

        if(passphrase == null) {
            passphrase = "";
        }

        List<String> mnemonicCode;
        try {
            mnemonicCode = Bip39MnemonicCode.INSTANCE.toMnemonic(entropy);
        } catch (MnemonicException.MnemonicLengthException e) {
            // cannot happen
            throw new RuntimeException(e);
        }
        this.seed = Bip39MnemonicCode.toSeed(mnemonicCode, passphrase);
        this.encryptedSeed = null;
        this.creationTimeSeconds = creationTimeSeconds;
    }

    private static byte[] getEntropy(SecureRandom random, int bits) {
        if(bits > MAX_SEED_ENTROPY_BITS) {
            throw new IllegalArgumentException("Requested entropy size too large");
        }

        byte[] seed = new byte[bits / 8];
        random.nextBytes(seed);
        return seed;
    }

    @Override
    public boolean isEncrypted() {
        return encryptedSeed != null;
    }

    public String toString() {
        if(isEncrypted()) {
            return encryptedSeed.toString();
        }

        return Utils.bytesToHex(seed);
    }

    /** Returns the seed as hex or null if encrypted. */
    public String toHexString() {
        return seed != null ? Utils.bytesToHex(seed) : null;
    }

    @Override
    public byte[] getSecretBytes() {
        return getSeedBytes();
    }

    public byte[] getSeedBytes() {
        return seed;
    }

    @Override
    public EncryptedData getEncryptedData() {
        return encryptedSeed;
    }

    @Override
    public EncryptionType getEncryptionType() {
        return EncryptionType.ENCRYPTED_SCRYPT_AES;
    }

    @Override
    public long getCreationTimeSeconds() {
        return creationTimeSeconds;
    }

    public void setCreationTimeSeconds(long creationTimeSeconds) {
        this.creationTimeSeconds = creationTimeSeconds;
    }

    public DeterministicSeed encrypt(KeyCrypter keyCrypter, KeyParameter aesKey) {
        if(encryptedSeed != null) {
            throw new IllegalArgumentException("Trying to encrypt seed twice");
        }

        EncryptedData encryptedSeed = keyCrypter.encrypt(seed, null, aesKey);
        return new DeterministicSeed(encryptedSeed, creationTimeSeconds);
    }

    public DeterministicSeed decrypt(KeyCrypter crypter, String passphrase, KeyParameter aesKey) {
        if(!isEncrypted()) {
            throw new IllegalStateException("Cannot decrypt unencrypted seed");
        }
        byte[] seed = crypter.decrypt(encryptedSeed, aesKey);
        return new DeterministicSeed(seed, passphrase, creationTimeSeconds);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DeterministicSeed other = (DeterministicSeed) o;
        return creationTimeSeconds == other.creationTimeSeconds
                && (isEncrypted() ? encryptedSeed.equals(other.encryptedSeed) : Arrays.equals(seed, other.seed));
    }

    @Override
    public int hashCode() {
        return Objects.hash(creationTimeSeconds, isEncrypted() ? encryptedSeed : seed);
    }
}
