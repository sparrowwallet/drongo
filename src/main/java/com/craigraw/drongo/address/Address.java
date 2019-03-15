package com.craigraw.drongo.address;

import com.craigraw.drongo.protocol.Base58;
import com.craigraw.drongo.protocol.Script;

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
}
