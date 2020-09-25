package com.sparrowwallet.drongo.address;

import com.sparrowwallet.drongo.protocol.Network;
import com.sparrowwallet.drongo.protocol.Script;
import com.sparrowwallet.drongo.protocol.ScriptType;

public class P2PKHAddress extends Address {
    public P2PKHAddress(Network network, byte[] pubKeyHash) {
        super(network, pubKeyHash);
    }

    public int getVersion() {
        return network.pkhVersion;
    }

    public ScriptType getScriptType() {
        return ScriptType.P2PKH;
    }

    public Script getOutputScript() {
        return getScriptType().getOutputScript(hash);
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
