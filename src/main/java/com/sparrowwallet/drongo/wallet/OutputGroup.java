package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.protocol.ScriptType;

import java.util.ArrayList;
import java.util.List;

import static com.sparrowwallet.drongo.protocol.Transaction.WITNESS_SCALE_FACTOR;

public class OutputGroup {
    private final List<BlockTransactionHashIndex> utxos = new ArrayList<>();
    private final ScriptType scriptType;
    private final int walletBlockHeight;
    private final long inputWeightUnits;
    private final double feeRate;
    private final double longTermFeeRate;
    private long value = 0;
    private long effectiveValue = 0;
    private long fee = 0;
    private long longTermFee = 0;
    private int depth = Integer.MAX_VALUE;
    private boolean allInputsFromWallet = true;
    private boolean spendLast;

    public OutputGroup(ScriptType scriptType, int walletBlockHeight, long inputWeightUnits, double feeRate, double longTermFeeRate) {
        this.scriptType = scriptType;
        this.walletBlockHeight = walletBlockHeight;
        this.inputWeightUnits = inputWeightUnits;
        this.feeRate = feeRate;
        this.longTermFeeRate = longTermFeeRate;
    }

    public void add(BlockTransactionHashIndex utxo, boolean allInputsFromWallet, boolean spendLast) {
        utxos.add(utxo);
        value += utxo.getValue();
        effectiveValue += utxo.getValue() - (long)(inputWeightUnits * feeRate / WITNESS_SCALE_FACTOR);
        fee += (long)(inputWeightUnits * feeRate / WITNESS_SCALE_FACTOR);
        longTermFee += (long)(inputWeightUnits * longTermFeeRate / WITNESS_SCALE_FACTOR);
        depth = utxo.getHeight() <= 0 ? 0 : Math.min(depth, walletBlockHeight - utxo.getHeight() + 1);
        this.allInputsFromWallet &= allInputsFromWallet;
        this.spendLast |= spendLast;
    }

    public void remove(BlockTransactionHashIndex utxo) {
        if(utxos.remove(utxo)) {
            value -= utxo.getValue();
            effectiveValue -= (utxo.getValue() - (long)(inputWeightUnits * feeRate / WITNESS_SCALE_FACTOR));
            fee -= (long)(inputWeightUnits * feeRate / WITNESS_SCALE_FACTOR);
            longTermFee -= (long)(inputWeightUnits * longTermFeeRate / WITNESS_SCALE_FACTOR);
        }
    }

    public List<BlockTransactionHashIndex> getUtxos() {
        return utxos;
    }

    public ScriptType getScriptType() {
        return scriptType;
    }

    public long getValue() {
        return value;
    }

    public long getEffectiveValue() {
        return effectiveValue;
    }

    public long getFee() {
        return fee;
    }

    public long getLongTermFee() {
        return longTermFee;
    }

    public int getDepth() {
        return depth;
    }

    public boolean isAllInputsFromWallet() {
        return allInputsFromWallet;
    }

    public boolean isSpendLast() {
        return spendLast;
    }

    public static class Filter {
        private final int minWalletConfirmations;
        private final int minExternalConfirmations;
        private final boolean includeSpendLast;

        public Filter(int minWalletConfirmations, int minExternalConfirmations, boolean includeSpendLast) {
            this.minWalletConfirmations = minWalletConfirmations;
            this.minExternalConfirmations = minExternalConfirmations;
            this.includeSpendLast = includeSpendLast;
        }

        public boolean isEligible(OutputGroup outputGroup) {
            if(outputGroup.isAllInputsFromWallet()) {
                return outputGroup.getDepth() >= minWalletConfirmations && (includeSpendLast || !outputGroup.isSpendLast());
            }

            return outputGroup.getDepth() >= minExternalConfirmations && (includeSpendLast || !outputGroup.isSpendLast());
        }
    }
}
