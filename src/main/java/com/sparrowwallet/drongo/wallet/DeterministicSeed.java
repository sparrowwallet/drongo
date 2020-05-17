package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.*;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;

public class DeterministicSeed implements EncryptableItem {
    public static final int DEFAULT_SEED_ENTROPY_BITS = 128;
    public static final int MAX_SEED_ENTROPY_BITS = 512;

    private final Type type;
    private final List<String> mnemonicCode;
    private final EncryptedData encryptedMnemonicCode;
    private final boolean needsPassphrase;
    private long creationTimeSeconds;

    //Session only storage
    private transient String passphrase;

    public DeterministicSeed(String mnemonicString, String passphrase, long creationTimeSeconds, Type type) {
        this(decodeMnemonicCode(mnemonicString), passphrase, creationTimeSeconds, type);
    }

    public DeterministicSeed(List<String> mnemonic, String passphrase, long creationTimeSeconds, Type type) {
        this(mnemonic, needsPassphrase(passphrase), creationTimeSeconds, type);
        this.passphrase = passphrase;
    }

    public DeterministicSeed(List<String> mnemonic, boolean needsPassphrase, long creationTimeSeconds, Type type) {
        this.mnemonicCode = mnemonic;
        this.encryptedMnemonicCode = null;
        this.needsPassphrase = needsPassphrase;
        this.creationTimeSeconds = creationTimeSeconds;
        this.type = type;
    }

    public DeterministicSeed(EncryptedData encryptedMnemonic, boolean needsPassphrase, long creationTimeSeconds, Type type) {
        this.mnemonicCode = null;
        this.encryptedMnemonicCode = encryptedMnemonic;
        this.needsPassphrase = needsPassphrase;
        this.creationTimeSeconds = creationTimeSeconds;
        this.type = type;
    }

    /**
     * Constructs a new BIP39 seed. See {@link Bip39MnemonicCode} for more
     * details on this scheme.
     * @param random Entropy source
     * @param bits number of bits, must be divisible by 32
     * @param passphrase A user supplied passphrase, or an empty string if there is no passphrase
     */
    public DeterministicSeed(SecureRandom random, int bits, String passphrase) {
        this(getEntropy(random, bits), passphrase, System.currentTimeMillis());
    }

    /**
     * Constructs a BIP39 seed from provided entropy. See {@link Bip39MnemonicCode} for more
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
        this.encryptedMnemonicCode = null;
        this.needsPassphrase = needsPassphrase(passphrase);
        this.creationTimeSeconds = creationTimeSeconds;
        this.type = Type.BIP39;
    }

    public static boolean needsPassphrase(String passphrase) {
        return passphrase != null && !passphrase.isEmpty();
    }

    public boolean needsPassphrase() {
        return needsPassphrase;
    }

    public String getPassphrase() {
        return passphrase;
    }

    public void setPassphrase(String passphrase) {
        this.passphrase = passphrase;
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
            return encryptedMnemonicCode.toString();
        }

        return getMnemonicString();
    }

    /** Returns the seed as hex or null if encrypted. */
    public String toHexString() throws MnemonicException {
        byte[] seed = getSeedBytes();
        return seed != null ? Utils.bytesToHex(seed) : null;
    }

    @Override
    public byte[] getSecretBytes() {
        return getMnemonicAsBytes();
    }

    public byte[] getSeedBytes() throws MnemonicException {
        if(passphrase == null && needsPassphrase) {
            throw new MnemonicException("Passphrase required but not provided");
        }

        return type.toSeed(mnemonicCode, passphrase);
    }

    @Override
    public EncryptedData getEncryptedData() {
        return encryptedMnemonicCode;
    }

    @Override
    public EncryptionType getEncryptionType() {
        return new EncryptionType(EncryptionType.Deriver.SCRYPT, EncryptionType.Crypter.AES_CBC_PKCS7);
    }

    @Override
    public long getCreationTimeSeconds() {
        return creationTimeSeconds;
    }

    public void setCreationTimeSeconds(long creationTimeSeconds) {
        this.creationTimeSeconds = creationTimeSeconds;
    }

    public Type getType() {
        return type;
    }

    public DeterministicSeed encrypt(String password) {
        if(encryptedMnemonicCode != null) {
            throw new IllegalArgumentException("Trying to encrypt twice");
        }
        if(mnemonicCode == null) {
            throw new IllegalArgumentException("Mnemonic missing so cannot encrypt");
        }
        KeyDeriver keyDeriver = getEncryptionType().getDeriver().getKeyDeriver();
        Key key = keyDeriver.deriveKey(password);

        KeyCrypter keyCrypter = getEncryptionType().getCrypter().getKeyCrypter();
        EncryptedData encryptedMnemonic = keyCrypter.encrypt(getMnemonicAsBytes(), null, key);
        DeterministicSeed seed = new DeterministicSeed(encryptedMnemonic, needsPassphrase, creationTimeSeconds, type);
        seed.setPassphrase(passphrase);

        return seed;
    }

    private byte[] getMnemonicAsBytes() {
        return getMnemonicString().getBytes(StandardCharsets.UTF_8);
    }

    public DeterministicSeed decrypt(String password) {
        if(!isEncrypted()) {
            throw new IllegalStateException("Cannot decrypt unencrypted seed");
        }
        KeyDeriver keyDeriver = getEncryptionType().getDeriver().getKeyDeriver(encryptedMnemonicCode.getKeySalt());
        Key key = keyDeriver.deriveKey(password);

        KeyCrypter keyCrypter = getEncryptionType().getCrypter().getKeyCrypter();
        List<String> mnemonic = decodeMnemonicCode(keyCrypter.decrypt(encryptedMnemonicCode, key));
        DeterministicSeed seed = new DeterministicSeed(mnemonic, needsPassphrase, creationTimeSeconds, type);
        seed.setPassphrase(passphrase);

        return seed;
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
        if(mnemonicCode != null) {
            type.check(mnemonicCode);
        }
    }

    byte[] getEntropyBytes() throws MnemonicException {
        return type.getEntropyBytes(mnemonicCode);
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
        DeterministicSeed seed;

        if(isEncrypted()) {
            seed = new DeterministicSeed(encryptedMnemonicCode.copy(), needsPassphrase, creationTimeSeconds, type);
        } else {
            seed = new DeterministicSeed(new ArrayList<>(mnemonicCode), needsPassphrase, creationTimeSeconds, type);
        }

        seed.setPassphrase(passphrase);
        return seed;
    }

    public enum Type {
        BIP39() {
            public byte[] getEntropyBytes(List<String> mnemonicCode) throws MnemonicException {
                return Bip39MnemonicCode.INSTANCE.toEntropy(mnemonicCode);
            }

            public void check(List<String> mnemonicCode) throws MnemonicException {
                Bip39MnemonicCode.INSTANCE.check(mnemonicCode);
            }

            public byte[] toSeed(List<String> mnemonicCode, String passphrase) {
                return Bip39MnemonicCode.toSeed(mnemonicCode, passphrase);
            }
        },
        ELECTRUM() {
            public byte[] getEntropyBytes(List<String> mnemonicCode) throws MnemonicException {
                throw new MnemonicException("Electrum seeds do not provide entropy bytes");
            }

            public void check(List<String> mnemonicCode) throws MnemonicException {
                ElectrumMnemonicCode.INSTANCE.check(mnemonicCode);
            }

            public byte[] toSeed(List<String> mnemonicCode, String passphrase) {
                return ElectrumMnemonicCode.toSeed(mnemonicCode, passphrase);
            }
        };

        public abstract byte[] getEntropyBytes(List<String> mnemonicCode) throws MnemonicException;

        public abstract void check(List<String> mnemonicCode) throws MnemonicException;

        public abstract byte[] toSeed(List<String> mnemonicCode, String passphrase);
    }
}
