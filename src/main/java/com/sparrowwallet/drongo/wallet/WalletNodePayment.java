package com.sparrowwallet.drongo.wallet;

public class WalletNodePayment extends Payment {
    private final WalletNode walletNode;

    public WalletNodePayment(WalletNode walletNode, String label, long amount, boolean sendMax) {
        this(walletNode, label, amount, sendMax, Type.DEFAULT);
    }

    public WalletNodePayment(WalletNode walletNode, String label, long amount, boolean sendMax, Type type) {
        super(walletNode.getAddress(), label, amount, sendMax, type);
        this.walletNode = walletNode;
    }

    public WalletNode getWalletNode() {
        return walletNode;
    }
}
