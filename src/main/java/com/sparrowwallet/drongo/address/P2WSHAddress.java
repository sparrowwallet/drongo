package com.sparrowwallet.drongo.address;

import com.sparrowwallet.drongo.protocol.*;

import com.sparrowwallet.drongo.protocol.Network;

public class P2WSHAddress extends Address {
    public P2WSHAddress(Network network, byte[] scriptHash) {
        super(network, scriptHash);
    }

    public int getVersion() {
        return 0;
    }

    public String getAddress() {
        return Bech32.encode(network.hrp, getVersion(), hash);
    }

    public ScriptType getScriptType() {
        return ScriptType.P2WSH;
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
        return "Witness Script Hash";
    }

    public static P2WSHAddress fromProgram(Network network, byte[] program) {
        return new P2WSHAddress(network, Sha256Hash.hash(program));
    }
}
