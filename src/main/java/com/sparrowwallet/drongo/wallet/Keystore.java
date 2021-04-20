package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.ExtendedKey;
import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.KeyPurpose;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.*;

import java.util.List;

public class Keystore {
    public static final String DEFAULT_LABEL = "Keystore 1";
    public static final int MAX_LABEL_LENGTH = 16;

    private String label;
    private KeystoreSource source = KeystoreSource.SW_WATCH;
    private WalletModel walletModel = WalletModel.SPARROW;
    private KeyDerivation keyDerivation;
    private ExtendedKey extendedPublicKey;
    private MasterPrivateExtendedKey masterPrivateExtendedKey;
    private DeterministicSeed seed;

    public Keystore() {
        this(DEFAULT_LABEL);
    }

    public Keystore(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }

    public String getScriptName() {
        return label.replace(" ", "");
    }

    public void setLabel(String label) {
        this.label = label;
    }

    public KeystoreSource getSource() {
        return source;
    }

    public void setSource(KeystoreSource source) {
        this.source = source;
    }

    public WalletModel getWalletModel() {
        return walletModel;
    }

    public void setWalletModel(WalletModel walletModel) {
        this.walletModel = walletModel;
    }

    public KeyDerivation getKeyDerivation() {
        return keyDerivation;
    }

    public void setKeyDerivation(KeyDerivation keyDerivation) {
        this.keyDerivation = keyDerivation;
    }

    public ExtendedKey getExtendedPublicKey() {
        return extendedPublicKey;
    }

    public void setExtendedPublicKey(ExtendedKey extendedPublicKey) {
        this.extendedPublicKey = extendedPublicKey;
    }

    public boolean hasMasterPrivateExtendedKey() {
        return masterPrivateExtendedKey != null;
    }

    public MasterPrivateExtendedKey getMasterPrivateExtendedKey() {
        return masterPrivateExtendedKey;
    }

    public void setMasterPrivateExtendedKey(MasterPrivateExtendedKey masterPrivateExtendedKey) {
        this.masterPrivateExtendedKey = masterPrivateExtendedKey;
    }

    public boolean hasSeed() {
        return seed != null;
    }

    public DeterministicSeed getSeed() {
        return seed;
    }

    public void setSeed(DeterministicSeed seed) {
        this.seed = seed;
    }

    public boolean hasPrivateKey() {
        return hasSeed() || hasMasterPrivateExtendedKey();
    }

    public DeterministicKey getMasterPrivateKey() throws MnemonicException {
        if(seed == null && masterPrivateExtendedKey == null) {
            throw new IllegalArgumentException("Keystore does not contain a master private key, or seed to derive one from");
        }

        if(seed != null) {
            if(seed.isEncrypted()) {
                throw new IllegalArgumentException("Seed is encrypted");
            }

            return HDKeyDerivation.createMasterPrivateKey(seed.getSeedBytes());
        }

        if(masterPrivateExtendedKey.isEncrypted()) {
            throw new IllegalArgumentException("Master private key is encrypted");
        }

        return masterPrivateExtendedKey.getPrivateKey();
    }

    public ExtendedKey getExtendedMasterPrivateKey() throws MnemonicException {
        return new ExtendedKey(getMasterPrivateKey(), new byte[4], ChildNumber.ZERO);
    }

    public ExtendedKey getExtendedMasterPublicKey() throws MnemonicException {
        return new ExtendedKey(getMasterPrivateKey().dropPrivateBytes(), new byte[4], ChildNumber.ZERO);
    }

    public ExtendedKey getExtendedPrivateKey() throws MnemonicException {
        List<ChildNumber> derivation = getKeyDerivation().getDerivation();
        DeterministicKey derivedKey = getExtendedMasterPrivateKey().getKey(derivation);
        ExtendedKey xprv = new ExtendedKey(derivedKey, derivedKey.getParentFingerprint(), derivation.isEmpty() ? ChildNumber.ZERO : derivation.get(derivation.size() - 1));
        //Recreate from xprv string to reset path to single ChildNumber at the derived depth
        return ExtendedKey.fromDescriptor(xprv.toString());
    }

    public DeterministicKey getKey(WalletNode walletNode) throws MnemonicException {
        return getKey(walletNode.getKeyPurpose(), walletNode.getIndex());
    }

    public DeterministicKey getKey(KeyPurpose keyPurpose, int keyIndex) throws MnemonicException {
        ExtendedKey extendedPrivateKey = getExtendedPrivateKey();
        List<ChildNumber> derivation = List.of(extendedPrivateKey.getKeyChildNumber(), keyPurpose.getPathIndex(), new ChildNumber(keyIndex));
        return extendedPrivateKey.getKey(derivation);
    }

    public DeterministicKey getPubKey(WalletNode walletNode) {
        return getPubKey(walletNode.getKeyPurpose(), walletNode.getIndex());
    }

    public DeterministicKey getPubKey(KeyPurpose keyPurpose, int keyIndex) {
        List<ChildNumber> derivation = List.of(extendedPublicKey.getKeyChildNumber(), keyPurpose.getPathIndex(), new ChildNumber(keyIndex));
        return extendedPublicKey.getKey(derivation);
    }

    public KeyDerivation getDerivation(KeyPurpose keyPurpose, int keyIndex) {
        return getKeyDerivation().extend(keyPurpose.getPathIndex()).extend(new ChildNumber(keyIndex));
    }

    public boolean isValid() {
        try {
            checkKeystore();
        } catch(InvalidKeystoreException e) {
            return false;
        }

        return true;
    }

    public void checkKeystore() throws InvalidKeystoreException {
        if(label == null) {
            throw new InvalidKeystoreException("No label specified");
        }

        if(source == null) {
            throw new InvalidKeystoreException("No source specified");
        }

        if(walletModel == null) {
            throw new InvalidKeystoreException("No wallet model specified");
        }

        if(keyDerivation == null) {
            throw new InvalidKeystoreException("No key derivation specified");
        }

        if(extendedPublicKey == null) {
            throw new InvalidKeystoreException("No extended public key specified");
        }

        if(label.isEmpty()) {
            throw new InvalidKeystoreException("Label too short");
        }

        if(label.replace(" ", "").length() > MAX_LABEL_LENGTH) {
            throw new InvalidKeystoreException("Label too long");
        }

        if(keyDerivation.getDerivationPath() == null || keyDerivation.getDerivationPath().isEmpty() || !KeyDerivation.isValid(keyDerivation.getDerivationPath())) {
            throw new InvalidKeystoreException("Invalid key derivation path of " + keyDerivation.getDerivationPath());
        }

        if(keyDerivation.getMasterFingerprint() == null || keyDerivation.getMasterFingerprint().length() != 8 || !Utils.isHex(keyDerivation.getMasterFingerprint())) {
            throw new InvalidKeystoreException("Invalid master fingerprint of " + keyDerivation.getMasterFingerprint());
        }

        if(source == KeystoreSource.SW_SEED) {
            if(seed == null && masterPrivateExtendedKey == null) {
                throw new InvalidKeystoreException("Source of " + source + " but no seed or master private key is present");
            }

            if((seed != null && !seed.isEncrypted()) || (masterPrivateExtendedKey != null && !masterPrivateExtendedKey.isEncrypted())) {
                try {
                    List<ChildNumber> derivation = getKeyDerivation().getDerivation();
                    DeterministicKey derivedKey = getExtendedMasterPrivateKey().getKey(derivation);
                    DeterministicKey derivedKeyPublicOnly = derivedKey.dropPrivateBytes().dropParent();
                    ExtendedKey xpub = new ExtendedKey(derivedKeyPublicOnly, derivedKey.getParentFingerprint(), derivation.isEmpty() ? ChildNumber.ZERO : derivation.get(derivation.size() - 1));
                    if(!xpub.equals(getExtendedPublicKey())) {
                        throw new InvalidKeystoreException("Specified extended public key does not match public key derived from seed");
                    }
                } catch(MnemonicException e) {
                    throw new InvalidKeystoreException("Invalid mnemonic specified for seed", e);
                }
            }
        }
    }

    public Keystore copy() {
        Keystore copy = new Keystore(label);
        copy.setSource(source);
        copy.setWalletModel(walletModel);
        if(keyDerivation != null) {
            copy.setKeyDerivation(keyDerivation.copy());
        }
        if(extendedPublicKey != null) {
            copy.setExtendedPublicKey(extendedPublicKey.copy());
        }
        if(masterPrivateExtendedKey != null) {
            copy.setMasterPrivateExtendedKey(masterPrivateExtendedKey.copy());
        }
        if(seed != null) {
            copy.setSeed(seed.copy());
        }
        return copy;
    }

    public static Keystore fromSeed(DeterministicSeed seed, List<ChildNumber> derivation) throws MnemonicException {
        Keystore keystore = new Keystore();
        keystore.setSeed(seed);
        keystore.setLabel(seed.getType().name());
        rederiveKeystoreFromMaster(keystore, derivation);
        return keystore;
    }

    public static Keystore fromMasterPrivateExtendedKey(MasterPrivateExtendedKey masterPrivateExtendedKey, List<ChildNumber> derivation) throws MnemonicException {
        Keystore keystore = new Keystore();
        keystore.setMasterPrivateExtendedKey(masterPrivateExtendedKey);
        keystore.setLabel("Master Key");
        rederiveKeystoreFromMaster(keystore, derivation);
        return keystore;
    }

    private static void rederiveKeystoreFromMaster(Keystore keystore, List<ChildNumber> derivation) throws MnemonicException {
        ExtendedKey xprv = keystore.getExtendedMasterPrivateKey();
        String masterFingerprint = Utils.bytesToHex(xprv.getKey().getFingerprint());
        DeterministicKey derivedKey = xprv.getKey(derivation);
        DeterministicKey derivedKeyPublicOnly = derivedKey.dropPrivateBytes().dropParent();
        ExtendedKey xpub = new ExtendedKey(derivedKeyPublicOnly, derivedKey.getParentFingerprint(), derivation.isEmpty() ? ChildNumber.ZERO : derivation.get(derivation.size() - 1));

        keystore.setSource(KeystoreSource.SW_SEED);
        keystore.setWalletModel(WalletModel.SPARROW);
        keystore.setKeyDerivation(new KeyDerivation(masterFingerprint, KeyDerivation.writePath(derivation)));
        keystore.setExtendedPublicKey(ExtendedKey.fromDescriptor(xpub.toString()));
    }

    public boolean isEncrypted() {
        return (seed != null && seed.isEncrypted()) || (masterPrivateExtendedKey != null && masterPrivateExtendedKey.isEncrypted());
    }

    public void encrypt(Key key) {
        if(hasSeed() && !seed.isEncrypted()) {
            seed = seed.encrypt(key);
        }
        if(hasMasterPrivateExtendedKey() && !masterPrivateExtendedKey.isEncrypted()) {
            masterPrivateExtendedKey = masterPrivateExtendedKey.encrypt(key);
        }
    }

    public void decrypt(CharSequence password) {
        if(hasSeed() && seed.isEncrypted()) {
            seed = seed.decrypt(password);
        }
        if(hasMasterPrivateExtendedKey() && masterPrivateExtendedKey.isEncrypted()) {
            masterPrivateExtendedKey = masterPrivateExtendedKey.decrypt(password);
        }
    }

    public void decrypt(Key key) {
        if(hasSeed() && seed.isEncrypted()) {
            seed = seed.decrypt(key);
        }
        if(hasMasterPrivateExtendedKey() && masterPrivateExtendedKey.isEncrypted()) {
            masterPrivateExtendedKey = masterPrivateExtendedKey.decrypt(key);
        }
    }

    public void clearPrivate() {
        if(hasSeed()) {
            seed.clear();
        }
        if(hasMasterPrivateExtendedKey()) {
            masterPrivateExtendedKey.clear();
        }
    }
}
