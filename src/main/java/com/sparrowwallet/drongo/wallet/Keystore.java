package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.ExtendedPublicKey;
import com.sparrowwallet.drongo.KeyDerivation;

public class Keystore {
    private String label;
    private KeyDerivation keyDerivation;
    private ExtendedPublicKey extendedPublicKey;

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
}
