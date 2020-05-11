package com.sparrowwallet.drongo.wallet;

public enum KeystoreSource {
    HW_USB("Connected Hardware Wallet"), HW_AIRGAPPED("Airgapped Hardware Wallet"), SW_SEED("Software Wallet"), SW_WATCH("Watch Only Wallet");

    private String displayName;

    KeystoreSource(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }
}
