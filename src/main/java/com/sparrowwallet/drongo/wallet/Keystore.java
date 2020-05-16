package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.ExtendedKey;
import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.*;

import java.util.List;

public class Keystore {
    public static final String DEFAULT_LABEL = "Keystore 1";

    private String label;
    private KeystoreSource source = KeystoreSource.SW_WATCH;
    private WalletModel walletModel = WalletModel.SPARROW;
    private KeyDerivation keyDerivation;
    private ExtendedKey extendedPublicKey;
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
        return label.replace(" ", "").toLowerCase();
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

    public DeterministicSeed getSeed() {
        return seed;
    }

    public void setSeed(DeterministicSeed seed) {
        this.seed = seed;
    }

    public DeterministicKey getMasterPrivateKey() throws MnemonicException {
        if(seed == null) {
            throw new IllegalArgumentException("Keystore does not contain a seed");
        }

        if(seed.isEncrypted()) {
            throw new IllegalArgumentException("Seed is encrypted");
        }

        return HDKeyDerivation.createMasterPrivateKey(seed.getSeedBytes());
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
        return new ExtendedKey(derivedKey, derivedKey.getParentFingerprint(), derivation.get(derivation.size() - 1));
    }

    public boolean isValid() {
        if(label == null || source == null || walletModel == null || keyDerivation == null || extendedPublicKey == null) {
            return false;
        }

        if(label.isEmpty() || label.replace(" ", "").length() > 16) {
            return false;
        }

        if(keyDerivation.getDerivationPath() == null || keyDerivation.getDerivationPath().isEmpty() || !KeyDerivation.isValid(keyDerivation.getDerivationPath())) {
            return false;
        }

        if(keyDerivation.getMasterFingerprint() == null || keyDerivation.getMasterFingerprint().length() != 8 || !Utils.isHex(keyDerivation.getMasterFingerprint())) {
            return false;
        }

        if(source == KeystoreSource.SW_SEED) {
            if(seed == null) {
                return false;
            }

            if(!seed.isEncrypted()) {
                try {
                    List<ChildNumber> derivation = getKeyDerivation().getDerivation();
                    DeterministicKey derivedKey = getExtendedMasterPrivateKey().getKey(derivation);
                    DeterministicKey derivedKeyPublicOnly = derivedKey.dropPrivateBytes().dropParent();
                    ExtendedKey xpub = new ExtendedKey(derivedKeyPublicOnly, derivedKey.getParentFingerprint(), derivation.get(derivation.size() - 1));
                    if(!xpub.equals(getExtendedPublicKey())) {
                        return false;
                    }
                } catch(MnemonicException e) {
                    return false;
                }
            }
        }

        return true;
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
        if(seed != null) {
            copy.setSeed(seed.copy());
        }
        return copy;
    }

    public static Keystore fromSeed(DeterministicSeed seed, List<ChildNumber> derivation) throws MnemonicException {
        Keystore keystore = new Keystore();
        keystore.setSeed(seed);
        ExtendedKey xprv = keystore.getExtendedMasterPrivateKey();
        String masterFingerprint = Utils.bytesToHex(xprv.getKey().getFingerprint());
        DeterministicKey derivedKey = xprv.getKey(derivation);
        DeterministicKey derivedKeyPublicOnly = derivedKey.dropPrivateBytes().dropParent();
        ExtendedKey xpub = new ExtendedKey(derivedKeyPublicOnly, derivedKey.getParentFingerprint(), derivation.get(derivation.size() - 1));

        keystore.setLabel(masterFingerprint);
        keystore.setSource(KeystoreSource.SW_SEED);
        keystore.setWalletModel(WalletModel.SPARROW);
        keystore.setKeyDerivation(new KeyDerivation(masterFingerprint, KeyDerivation.writePath(derivation)));
        keystore.setExtendedPublicKey(ExtendedKey.fromDescriptor(xpub.toString()));

        return keystore;
    }

    public boolean hasSeed() {
        return seed != null;
    }

    public boolean isEncrypted() {
        return seed != null && seed.isEncrypted();
    }

    public void encrypt(String password) {
        if(seed != null && !seed.isEncrypted()) {
            KeyCrypter keyCrypter = new ScryptKeyCrypter();
            seed = seed.encrypt(keyCrypter, keyCrypter.deriveKey(password));
        }
    }

    public void decrypt(String password) {
        if(seed != null && seed.isEncrypted()) {
            KeyCrypter keyCrypter = new ScryptKeyCrypter(seed.getEncryptedData().getKeySalt());
            seed = seed.decrypt(keyCrypter, keyCrypter.deriveKey(password));
        }
    }
}
