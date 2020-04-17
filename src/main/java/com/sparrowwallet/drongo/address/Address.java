package com.sparrowwallet.drongo.address;

import com.sparrowwallet.drongo.protocol.Base58;
import com.sparrowwallet.drongo.protocol.ScriptType;

public abstract class Address {
    protected final byte[] hash;

    public Address(byte[] hash) {
        this.hash = hash;
    }

    public byte[] getHash() {
        return hash;
    }

    public String getAddress() {
        return Base58.encodeChecked(getVersion(), hash);
    }

    public String toString() {
        return getAddress();
    }

    public abstract int getVersion();

    public abstract ScriptType getScriptType();

    public abstract byte[] getOutputScriptData();

    public abstract String getOutputScriptDataType();

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
