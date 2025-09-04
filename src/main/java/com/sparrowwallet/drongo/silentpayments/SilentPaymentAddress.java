package com.sparrowwallet.drongo.silentpayments;

import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.protocol.Bech32;

import java.util.Arrays;

public class SilentPaymentAddress {
    private final ECKey scanAddress;
    private final ECKey spendAddress;

    public SilentPaymentAddress(ECKey scanAddress, ECKey spendAddress) {
        this.scanAddress = scanAddress;
        this.spendAddress = spendAddress;
    }

    public ECKey getScanKey() {
        return scanAddress;
    }

    public ECKey getSpendKey() {
        return spendAddress;
    }

    public String getAddress() {
        byte[] keys = Utils.concat(scanAddress.getPubKey(), spendAddress.getPubKey());
        return Bech32.encode(Network.get().getSilentPaymentsAddressHrp(), 0, Bech32.Encoding.BECH32M, keys);
    }

    public static SilentPaymentAddress from(String address) {
        Bech32.Bech32Data data = Bech32.decode(address, 1023);
        if(data.encoding != Bech32.Encoding.BECH32M) {
            throw new IllegalArgumentException("Invalid silent payments address encoding");
        }

        if(!Network.get().getSilentPaymentsAddressHrp().equals(data.hrp)) {
            throw new IllegalArgumentException("Invalid silent payments address hrp");
        }

        int witnessVersion = data.data[0];
        if(witnessVersion != 0) {
            throw new UnsupportedOperationException("Unsupported silent payments address witness version");
        }

        byte[] convertedProgram = Arrays.copyOfRange(data.data, 1, data.data.length);
        byte[] witnessProgram = Bech32.convertBits(convertedProgram, 0, convertedProgram.length, 5, 8, false);

        if(witnessProgram.length != 66) {
            throw new IllegalArgumentException("Invalid silent payments address witness length");
        }

        ECKey scanPubKey = ECKey.fromPublicOnly(Arrays.copyOfRange(witnessProgram, 0, 33));
        ECKey spendPubKey = ECKey.fromPublicOnly(Arrays.copyOfRange(witnessProgram, 33, 66));

        return new SilentPaymentAddress(scanPubKey, spendPubKey);
    }

    @Override
    public String toString() {
        return getAddress();
    }

    @Override
    public final boolean equals(Object o) {
        if(this == o) {
            return true;
        }
        if(!(o instanceof SilentPaymentAddress that)) {
            return false;
        }

        return getAddress().equals(that.getAddress());
    }

    @Override
    public int hashCode() {
        return getAddress().hashCode();
    }
}
