package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.SecureString;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.*;

import java.security.SecureRandom;
import java.util.*;

public class DeterministicSeed extends Persistable implements EncryptableItem {
    public static final int DEFAULT_SEED_ENTROPY_BITS = 128;
    public static final int MAX_SEED_ENTROPY_BITS = 512;

    private final Type type;
    private final List<String> mnemonicCode;
    private final EncryptedData encryptedMnemonicCode;
    private final boolean needsPassphrase;
    private long creationTimeSeconds;

    //Session only storage
    private transient SecureString passphrase;

    public DeterministicSeed(CharSequence mnemonicString, String passphrase, long creationTimeSeconds, Type type) {
        this(decodeMnemonicCode(mnemonicString), passphrase, creationTimeSeconds, type);
    }

    public DeterministicSeed(List<String> mnemonic, String passphrase, long creationTimeSeconds, Type type) {
        this(mnemonic, needsPassphrase(passphrase), creationTimeSeconds, type);
        this.passphrase = (passphrase == null ? null : new SecureString(passphrase));
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
        this.passphrase = new SecureString(passphrase);
        this.creationTimeSeconds = creationTimeSeconds;
        this.type = Type.BIP39;
    }

    private static boolean needsPassphrase(String passphrase) {
        return passphrase != null && !passphrase.isEmpty();
    }

    public boolean needsPassphrase() {
        return needsPassphrase;
    }

    public SecureString getPassphrase() {
        return passphrase;
    }

    public void setPassphrase(SecureString passphrase) {
        this.passphrase = passphrase;
    }

    public void setPassphrase(String passphrase) {
        this.passphrase = new SecureString(passphrase);
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

        return type.toSeed(mnemonicCode, passphrase == null ? null : passphrase.asString());
    }

    @Override
    public EncryptedData getEncryptedData() {
        return encryptedMnemonicCode;
    }

    @Override
    public EncryptionType getEncryptionType() {
        return new EncryptionType(EncryptionType.Deriver.ARGON2, EncryptionType.Crypter.AES_CBC_PKCS7);
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

    public DeterministicSeed encrypt(Key key) {
        if(encryptedMnemonicCode != null) {
            throw new IllegalArgumentException("Trying to encrypt twice");
        }
        if(mnemonicCode == null) {
            throw new IllegalArgumentException("Mnemonic missing so cannot encrypt");
        }

        KeyCrypter keyCrypter = getEncryptionType().getCrypter().getKeyCrypter();
        byte[] mnemonicBytes = getMnemonicAsBytes();
        EncryptedData encryptedMnemonic = keyCrypter.encrypt(mnemonicBytes, null, key);
        Arrays.fill(mnemonicBytes != null ? mnemonicBytes : new byte[0], (byte)0);
        
        DeterministicSeed seed = new DeterministicSeed(encryptedMnemonic, needsPassphrase, creationTimeSeconds, type);
        seed.setId(getId());
        seed.setPassphrase(passphrase);

        return seed;
    }

    private byte[] getMnemonicAsBytes() {
        SecureString mnemonicString = getMnemonicString();
        if(mnemonicString == null) {
            return null;
        }

        byte[] mnemonicBytes = SecureString.toBytesUTF8(mnemonicString);
        mnemonicString.clear();

        return mnemonicBytes;
    }

    public DeterministicSeed decrypt(CharSequence password) {
        if(!isEncrypted()) {
            throw new IllegalStateException("Cannot decrypt unencrypted seed");
        }

        KeyDeriver keyDeriver = getEncryptionType().getDeriver().getKeyDeriver(encryptedMnemonicCode.getKeySalt());
        Key key = keyDeriver.deriveKey(password);
        DeterministicSeed seed = decrypt(key);
        seed.setId(getId());
        key.clear();

        return seed;
    }

    public DeterministicSeed decrypt(Key key) {
        if(!isEncrypted()) {
            throw new IllegalStateException("Cannot decrypt unencrypted seed");
        }

        KeyCrypter keyCrypter = getEncryptionType().getCrypter().getKeyCrypter();
        byte[] decrypted = keyCrypter.decrypt(encryptedMnemonicCode, key);
        List<String> mnemonic = decodeMnemonicCode(decrypted);
        Arrays.fill(decrypted, (byte)0);

        DeterministicSeed seed = new DeterministicSeed(mnemonic, needsPassphrase, creationTimeSeconds, type);
        seed.setId(getId());
        seed.setPassphrase(passphrase);

        return seed;
    }

    @Override
    public String toString() {
        return "DeterministicSeed{" +
                "type=" + type +
                ", encryptedMnemonicCode=" + encryptedMnemonicCode +
                ", needsPassphrase=" + needsPassphrase +
                '}';
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

    public void clear() {
        if(mnemonicCode != null) {
            mnemonicCode.clear();
        }
        if(passphrase != null) {
            passphrase = new SecureString("");
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
    public SecureString getMnemonicString() {
        StringBuilder builder = new StringBuilder();
        if(mnemonicCode != null) {
            for(String word : mnemonicCode) {
                builder.append(word);
                builder.append(' ');
            }

            if(builder.length() > 0) {
                builder.setLength(builder.length() - 1);
            }

            return new SecureString(builder);
        }

        return null;
    }

    private static List<String> decodeMnemonicCode(byte[] mnemonicCode) {
        SecureString secureString = SecureString.fromBytesUTF8(mnemonicCode);
        List<String> words = decodeMnemonicCode(secureString);
        secureString.clear();

        return words;
    }

    private static List<String> decodeMnemonicCode(CharSequence mnemonicCode) {
        List<String> words = new ArrayList<>();
        StringBuilder word = new StringBuilder();
        for(int i = 0; i < mnemonicCode.length(); i++) {
            char c = mnemonicCode.charAt(i);
            if(c != ' ') {
                word.append(mnemonicCode.charAt(i));
            }
            if(c == ' ' || i == mnemonicCode.length() - 1) {
                words.add(word.toString());

                for(int j = 0; j < word.length(); j++) {
                    word.setCharAt(j, ' ');
                }
                word = new StringBuilder();
            }
        }

        return words;
    }

    public DeterministicSeed copy() {
        DeterministicSeed seed;

        if(isEncrypted()) {
            seed = new DeterministicSeed(encryptedMnemonicCode.copy(), needsPassphrase, creationTimeSeconds, type);
        } else {
            seed = new DeterministicSeed(new ArrayList<>(mnemonicCode), needsPassphrase, creationTimeSeconds, type);
        }

        seed.setId(getId());
        seed.setPassphrase(passphrase);
        return seed;
    }

    public enum Type {
        BIP39("Mnemonic Words (BIP39)") {
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
        ELECTRUM("Mnemonic Words (Electrum Seed Version System)") {
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

        Type(String name) {
            this.name = name;
        }

        private final String name;

        public String getName() {
            return name;
        }

        public abstract byte[] getEntropyBytes(List<String> mnemonicCode) throws MnemonicException;

        public abstract void check(List<String> mnemonicCode) throws MnemonicException;

        public abstract byte[] toSeed(List<String> mnemonicCode, String passphrase);
    }
}
