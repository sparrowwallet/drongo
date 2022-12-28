package com.sparrowwallet.drongo.wallet;

public class WalletConfig extends Persistable {
    private byte[] iconData;
    private boolean userIcon;
    private boolean usePayNym;

    public WalletConfig() {
    }

    public WalletConfig(byte[] iconData, boolean userIcon, boolean usePayNym) {
        this.iconData = iconData;
        this.userIcon = userIcon;
        this.usePayNym = usePayNym;
    }

    public byte[] getIconData() {
        return iconData;
    }

    public boolean isUserIcon() {
        return userIcon;
    }

    public void setIconData(byte[] iconData, boolean userIcon) {
        this.iconData = iconData;
        this.userIcon = userIcon;
    }

    public boolean isUsePayNym() {
        return usePayNym;
    }

    public void setUsePayNym(boolean usePayNym) {
        this.usePayNym = usePayNym;
    }

    public WalletConfig copy() {
        return new WalletConfig(iconData, userIcon, usePayNym);
    }
}
