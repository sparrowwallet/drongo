package com.sparrowwallet.drongo.wallet;

import java.util.ArrayList;
import java.util.List;

import static com.sparrowwallet.drongo.protocol.Transaction.WITNESS_SCALE_FACTOR;

public class OutputGroup {
    private final List<BlockTransactionHashIndex> utxos = new ArrayList<>();
    private final long inputWeightUnits;
    private final double feeRate;
    private final double longTermFeeRate;
    private long value = 0;
    private long effectiveValue = 0;
    private long fee = 0;
    private long longTermFee = 0;

    public OutputGroup(long inputWeightUnits, double feeRate, double longTermFeeRate) {
        this.inputWeightUnits = inputWeightUnits;
        this.feeRate = feeRate;
        this.longTermFeeRate = longTermFeeRate;
    }

    public OutputGroup(long inputWeightUnits, double feeRate, double longTermFeeRate, BlockTransactionHashIndex utxo) {
        this.inputWeightUnits = inputWeightUnits;
        this.feeRate = feeRate;
        this.longTermFeeRate = longTermFeeRate;
        add(utxo);
    }

    public void add(BlockTransactionHashIndex utxo) {
        utxos.add(utxo);
        value += utxo.getValue();
        effectiveValue += utxo.getValue() - (long)(inputWeightUnits * feeRate / WITNESS_SCALE_FACTOR);
        fee += (long)(inputWeightUnits * feeRate / WITNESS_SCALE_FACTOR);
        longTermFee += (long)(inputWeightUnits * longTermFeeRate / WITNESS_SCALE_FACTOR);
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
}
