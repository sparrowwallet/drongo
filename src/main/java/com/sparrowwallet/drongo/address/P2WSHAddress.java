package com.sparrowwallet.drongo.address;

import com.sparrowwallet.drongo.protocol.*;

import static com.sparrowwallet.drongo.address.P2WPKHAddress.HRP;

public class P2WSHAddress extends Address {
    public P2WSHAddress(byte[] scriptHash) {
        super(scriptHash);
    }

    public int getVersion() {
        return 0;
    }

    public String getAddress() {
        return Bech32.encode(HRP, getVersion(), hash);
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

    public static P2WSHAddress fromProgram(byte[] program) {
        return new P2WSHAddress(Sha256Hash.hash(program));
    }
}
