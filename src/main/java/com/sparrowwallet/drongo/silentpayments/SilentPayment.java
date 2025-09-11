package com.sparrowwallet.drongo.silentpayments;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.address.Address;
import com.sparrowwallet.drongo.address.P2TRAddress;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.wallet.Payment;

import java.util.Set;

public class SilentPayment extends Payment {
    public static final Set<ScriptType> VALID_INPUT_SCRIPT_TYPES = Set.of(ScriptType.P2PKH, ScriptType.P2SH_P2WPKH, ScriptType.P2WPKH, ScriptType.P2TR);

    private final SilentPaymentAddress silentPaymentAddress;

    public SilentPayment(SilentPaymentAddress silentPaymentAddress, String label, long amount, boolean sendMax) {
        super(getDummyAddress(), label, amount, sendMax);
        this.silentPaymentAddress = silentPaymentAddress;
    }

    public static Address getDummyAddress() {
        return new P2TRAddress(Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000000"));
    }

    public SilentPaymentAddress getSilentPaymentAddress() {
        return silentPaymentAddress;
    }
}
