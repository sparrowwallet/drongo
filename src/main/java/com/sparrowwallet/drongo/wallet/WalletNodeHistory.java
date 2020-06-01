package com.sparrowwallet.drongo.wallet;

import java.util.Set;
import java.util.TreeSet;

public class WalletNodeHistory {
    private final Set<BlockchainTransactionHashIndex> receivedTXOs;
    private final Set<BlockchainTransactionHashIndex> spentTXOs;
    private final Set<BlockchainTransactionHashIndex> spendingTXIs;

    public WalletNodeHistory(Set<BlockchainTransactionHashIndex> receivedTXOs, Set<BlockchainTransactionHashIndex> spentTXOs, Set<BlockchainTransactionHashIndex> spendingTXIs) {
        this.receivedTXOs = receivedTXOs;
        this.spentTXOs = spentTXOs;
        this.spendingTXIs = spendingTXIs;
    }

    public Set<BlockchainTransactionHashIndex> getReceivedTXOs() {
        return receivedTXOs;
    }

    public Set<BlockchainTransactionHashIndex> getSpentTXOs() {
        return spentTXOs;
    }

    public Set<BlockchainTransactionHashIndex> getSpendingTXIs() {
        return spendingTXIs;
    }

    public Set<BlockchainTransactionHashIndex> getUnspentTXOs() {
        Set<BlockchainTransactionHashIndex> unspentTXOs = new TreeSet<>(receivedTXOs);
        unspentTXOs.removeAll(spentTXOs);

        return unspentTXOs;
    }
}
