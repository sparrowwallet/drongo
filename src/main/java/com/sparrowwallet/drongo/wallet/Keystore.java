package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.ExtendedKey;
import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ChildNumber;
import com.sparrowwallet.drongo.crypto.DeterministicKey;
import com.sparrowwallet.drongo.crypto.HDKeyDerivation;

public class Keystore {
    public static final String DEFAULT_LABEL = "Keystore 1";

    private String label;
    private KeystoreSource source = KeystoreSource.SW_WATCH;
    private WalletModel walletModel = WalletModel.SPARROW;
    private KeyDerivation keyDerivation;
    private ExtendedKey extendedPublicKey;
    private byte[] seed;

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

    public byte[] getSeed() {
        return seed;
    }

    public void setSeed(byte[] seed) {
        this.seed = seed;
    }

    public DeterministicKey getMasterPrivateKey() {
        if(seed == null) {
            throw new IllegalArgumentException("Keystore does not contain a seed");
        }

        return HDKeyDerivation.createMasterPrivateKey(seed);
    }

    public ExtendedKey getExtendedPrivateKey() {
        return new ExtendedKey(getMasterPrivateKey(), new byte[4], ChildNumber.ZERO);
    }

    public boolean isValid() {
        if(label == null || source == null || walletModel == null || keyDerivation == null || extendedPublicKey == null) {
            return false;
        }

        if(keyDerivation.getDerivationPath() == null || !KeyDerivation.isValid(keyDerivation.getDerivationPath())) {
            return false;
        }

        if(keyDerivation.getMasterFingerprint() == null || keyDerivation.getMasterFingerprint().length() != 8 || !Utils.isHex(keyDerivation.getMasterFingerprint())) {
            return false;
        }

        //TODO: If source is SW_SEED, check seed field is filled

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
        return copy;
    }
}
