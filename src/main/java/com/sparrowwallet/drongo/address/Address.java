package com.sparrowwallet.drongo.address;

import com.sparrowwallet.drongo.protocol.Base58;
import com.sparrowwallet.drongo.protocol.Script;

public abstract class Address {
    protected final byte[] pubKeyHash;

    public Address(byte[] pubKeyHash) {
        this.pubKeyHash = pubKeyHash;
    }

    public byte[] getPubKeyHash() {
        return pubKeyHash;
    }

    public String getAddress() {
        return Base58.encodeChecked(getVersion(), pubKeyHash);
    }

    public String toString() {
        return getAddress();
    }

    public abstract int getVersion();

    public abstract Script getOutputScript();

    public boolean equals(Object obj) {
        if(!(obj instanceof Address)) {
            return false;
        }

        Address address = (Address)obj;
        return address.getAddress().equals(this.getAddress());
    }

    public int hashCode() {
        return getAddress().hashCode();
    }
}
