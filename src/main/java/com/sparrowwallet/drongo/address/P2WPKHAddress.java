package com.sparrowwallet.drongo.address;

import com.sparrowwallet.drongo.protocol.Bech32;
import com.sparrowwallet.drongo.protocol.Network;
import com.sparrowwallet.drongo.protocol.Script;
import com.sparrowwallet.drongo.protocol.ScriptType;

public class P2WPKHAddress extends Address {

    public P2WPKHAddress(Network network, byte[] pubKeyHash) {
        super(network, pubKeyHash);
    }

    public int getVersion() {
        return 0;
    }

    public String getAddress() {
        return Bech32.encode(network.hrp, getVersion(), hash);
    }

    public ScriptType getScriptType() {
        return ScriptType.P2WPKH;
    }

    @Override
    public Script getOutputScript() {
        return getScriptType().getOutputScript(hash);
    }

    @Override
    public byte[] getOutputScriptData() {
        return hash;
    }

    @Override
    public String getOutputScriptDataType() {
        return "Witness Public Key Hash";
    }
}
