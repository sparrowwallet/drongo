package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.protocol.Transaction;

public class CoinbaseTxoFilter implements TxoFilter {
    private final Wallet wallet;

    public CoinbaseTxoFilter(Wallet wallet) {
        this.wallet = wallet;
    }

    @Override
    public boolean isEligible(BlockTransactionHashIndex candidate) {
        //Disallow immature coinbase outputs
        BlockTransaction blockTransaction = wallet.getWalletTransaction(candidate.getHash());
        if(blockTransaction != null && blockTransaction.getTransaction() != null && blockTransaction.getTransaction().isCoinBase()
            && wallet.getStoredBlockHeight() != null && candidate.getConfirmations(wallet.getStoredBlockHeight()) < Transaction.COINBASE_MATURITY_THRESHOLD) {
            return false;
        }

        return true;
    }
}
