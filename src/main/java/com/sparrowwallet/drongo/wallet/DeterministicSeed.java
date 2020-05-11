package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.EncryptableItem;
import com.sparrowwallet.drongo.crypto.EncryptedData;
import com.sparrowwallet.drongo.crypto.EncryptionType;
import com.sparrowwallet.drongo.crypto.KeyCrypter;
import org.bouncycastle.crypto.params.KeyParameter;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;

public class DeterministicSeed implements EncryptableItem {
    public static final int DEFAULT_SEED_ENTROPY_BITS = 128;
    public static final int MAX_SEED_ENTROPY_BITS = 512;

    private final byte[] seed;
    private final List<String> mnemonicCode;

    private final EncryptedData encryptedSeed;
    private final EncryptedData encryptedMnemonicCode;

    private long creationTimeSeconds;

    public DeterministicSeed(String mnemonicString, byte[] seed, String passphrase, long creationTimeSeconds) {
        this(decodeMnemonicCode(mnemonicString), seed, passphrase, creationTimeSeconds);
    }

    public DeterministicSeed(byte[] seed, List<String> mnemonic, long creationTimeSeconds) {
        this.seed = seed;
        this.encryptedSeed = null;
        this.mnemonicCode = mnemonic;
        this.encryptedMnemonicCode = null;
        this.creationTimeSeconds = creationTimeSeconds;
    }

    public DeterministicSeed(EncryptedData encryptedMnemonic, EncryptedData encryptedSeed, long creationTimeSeconds) {
        this.seed = null;
        this.encryptedSeed = encryptedSeed;
        this.mnemonicCode = null;
        this.encryptedMnemonicCode = encryptedMnemonic;
        this.creationTimeSeconds = creationTimeSeconds;
    }

    /**
     * Constructs a seed from a BIP 39 mnemonic code. See {@link Bip39MnemonicCode} for more
     * details on this scheme.
     * @param mnemonicCode A list of words.
     * @param seed The derived seed, or pass null to derive it from mnemonicCode (slow)
     * @param passphrase A user supplied passphrase, or an empty string if there is no passphrase
     * @param creationTimeSeconds When the seed was originally created, UNIX time.
     */
    public DeterministicSeed(List<String> mnemonicCode, byte[] seed, String passphrase, long creationTimeSeconds) {
        this((seed != null ? seed : Bip39MnemonicCode.toSeed(mnemonicCode, passphrase)), mnemonicCode, creationTimeSeconds);
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

        try {
            this.mnemonicCode = Bip39MnemonicCode.INSTANCE.toMnemonic(entropy);
        } catch (MnemonicException.MnemonicLengthException e) {
            // cannot happen
            throw new RuntimeException(e);
        }
        this.seed = Bip39MnemonicCode.toSeed(mnemonicCode, passphrase);
        this.encryptedMnemonicCode = null;
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
        if(mnemonicCode != null && encryptedMnemonicCode != null) {
            throw new IllegalStateException("Cannot be in a encrypted and unencrypted state");
        }

        return encryptedMnemonicCode != null;
    }

    @Override
    public String toString() {
        if(isEncrypted()) {
            return encryptedSeed.toString();
        }

        return toHexString();
    }

    /** Returns the seed as hex or null if encrypted. */
    public String toHexString() {
        return seed != null ? Utils.bytesToHex(seed) : null;
    }

    @Override
    public byte[] getSecretBytes() {
        return getMnemonicAsBytes();
    }

    public byte[] getSeedBytes() {
        return seed;
    }

    @Override
    public EncryptedData getEncryptedData() {
        return encryptedMnemonicCode;
    }

    @Override
    public EncryptionType getEncryptionType() {
        return EncryptionType.ENCRYPTED_SCRYPT_AES;
    }

    public EncryptedData getEncryptedSeedData() {
        return encryptedSeed;
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
        if(mnemonicCode == null) {
            throw new IllegalArgumentException("Mnemonic missing so cannot encrypt");
        }
        EncryptedData encryptedMnemonic = keyCrypter.encrypt(getMnemonicAsBytes(), null, aesKey);
        EncryptedData encryptedSeed = keyCrypter.encrypt(seed, null, aesKey);
        return new DeterministicSeed(encryptedMnemonic, encryptedSeed, creationTimeSeconds);
    }

    private byte[] getMnemonicAsBytes() {
        return getMnemonicString().getBytes(StandardCharsets.UTF_8);
    }

    public DeterministicSeed decrypt(KeyCrypter crypter, String passphrase, KeyParameter aesKey) {
        if(!isEncrypted()) {
            throw new IllegalStateException("Cannot decrypt unencrypted seed");
        }
        List<String> mnemonic = decodeMnemonicCode(crypter.decrypt(encryptedMnemonicCode, aesKey));
        byte[] seed = encryptedSeed == null ? null : crypter.decrypt(encryptedSeed, aesKey);
        return new DeterministicSeed(mnemonic, seed, passphrase, creationTimeSeconds);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DeterministicSeed other = (DeterministicSeed) o;
        return creationTimeSeconds == other.creationTimeSeconds
            && Objects.equals(encryptedMnemonicCode, other.encryptedMnemonicCode)
            && Objects.equals(mnemonicCode, other.mnemonicCode);
    }

    @Override
    public int hashCode() {
        return Objects.hash(creationTimeSeconds, encryptedMnemonicCode, mnemonicCode);
    }

    /**
     * Check if our mnemonic is a valid mnemonic phrase for our word list.
     * Does nothing if we are encrypted.
     *
     * @throws MnemonicException if check fails
     */
    public void check() throws MnemonicException {
        if (mnemonicCode != null) {
            Bip39MnemonicCode.INSTANCE.check(mnemonicCode);
        }
    }

    byte[] getEntropyBytes() throws MnemonicException {
        return Bip39MnemonicCode.INSTANCE.toEntropy(mnemonicCode);
    }

    /** Get the mnemonic code, or null if unknown. */
    public List<String> getMnemonicCode() {
        return mnemonicCode;
    }

    /** Get the mnemonic code as string, or null if unknown. */
    public String getMnemonicString() {
        StringJoiner joiner = new StringJoiner(" ");
        if(mnemonicCode != null) {
            for(String word : mnemonicCode) {
                joiner.add(word);
            }

            return joiner.toString();
        }

        return null;
    }

    private static List<String> decodeMnemonicCode(byte[] mnemonicCode) {
        return decodeMnemonicCode(new String(mnemonicCode, StandardCharsets.UTF_8));
    }

    private static List<String> decodeMnemonicCode(String mnemonicCode) {
        return Arrays.asList(mnemonicCode.split(" "));
    }

    public DeterministicSeed copy() {
        if(isEncrypted()) {
            return new DeterministicSeed(encryptedMnemonicCode.copy(), encryptedSeed.copy(), creationTimeSeconds);
        }

        return new DeterministicSeed(Arrays.copyOf(seed, seed.length), new ArrayList<>(mnemonicCode), creationTimeSeconds);
    }
}
