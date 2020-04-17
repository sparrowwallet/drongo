package com.sparrowwallet.drongo.address;

import com.sparrowwallet.drongo.protocol.ScriptType;

public class P2PKHAddress extends Address {
    public P2PKHAddress(byte[] pubKeyHash) {
        super(pubKeyHash);
    }

    public int getVersion() {
        return 0;
    }

    public ScriptType getScriptType() {
        return ScriptType.P2PKH;
    }

    @Override
    public byte[] getOutputScriptData() {
        return hash;
    }

    @Override
    public String getOutputScriptDataType() {
        return "Public Key Hash";
    }
}
