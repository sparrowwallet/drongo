package com.sparrowwallet.drongo.dns;

import com.sparrowwallet.drongo.address.Address;
import com.sparrowwallet.drongo.silentpayments.SilentPaymentAddress;

import java.util.Objects;

public class DnsAddress {
    private final Address address;
    private final SilentPaymentAddress silentPaymentAddress;

    public DnsAddress(Address address) {
        this.address = address;
        this.silentPaymentAddress = null;
    }

    public DnsAddress(SilentPaymentAddress silentPaymentAddress) {
        this.address = null;
        this.silentPaymentAddress = silentPaymentAddress;
    }

    @Override
    public final boolean equals(Object o) {
        if(this == o) {
            return true;
        }
        if(!(o instanceof DnsAddress that)) {
            return false;
        }

        return Objects.equals(address, that.address) && Objects.equals(silentPaymentAddress, that.silentPaymentAddress);
    }

    @Override
    public int hashCode() {
        int result = Objects.hashCode(address);
        result = 31 * result + Objects.hashCode(silentPaymentAddress);
        return result;
    }
}
