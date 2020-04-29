package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.ExtendedPublicKey;
import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.Utils;

public class Keystore {
    public static final String DEFAULT_LABEL = "Keystore 1";

    private String label;
    private KeystoreSource source = KeystoreSource.SW_WATCH;
    private WalletModel walletModel = WalletModel.SPARROW;
    private KeyDerivation keyDerivation;
    private ExtendedPublicKey extendedPublicKey;

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

    public ExtendedPublicKey getExtendedPublicKey() {
        return extendedPublicKey;
    }

    public void setExtendedPublicKey(ExtendedPublicKey extendedPublicKey) {
        this.extendedPublicKey = extendedPublicKey;
    }

    public boolean isValid() {
        if(label == null || keyDerivation == null || extendedPublicKey == null) {
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
        if(keyDerivation != null) {
            copy.setKeyDerivation(keyDerivation.copy());
        }
        if(extendedPublicKey != null) {
            copy.setExtendedPublicKey(extendedPublicKey.copy());
        }
        return copy;
    }
}
