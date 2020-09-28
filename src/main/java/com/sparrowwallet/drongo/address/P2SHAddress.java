package com.sparrowwallet.drongo.address;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.protocol.Network;
import com.sparrowwallet.drongo.protocol.Script;
import com.sparrowwallet.drongo.protocol.ScriptType;

public class P2SHAddress extends Address {
    public P2SHAddress(Network network, byte[] scriptHash) {
        super(network, scriptHash);
    }

    public int getVersion() {
        return network.shVersion;
    }

    @Override
    public ScriptType getScriptType() {
        return ScriptType.P2SH;
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
        return "Script Hash";
    }

    public static P2SHAddress fromProgram(Network network, byte[] program) {
        return new P2SHAddress(network, Utils.sha256hash160(program));
    }
}
