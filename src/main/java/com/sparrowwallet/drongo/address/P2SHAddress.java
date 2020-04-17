package com.sparrowwallet.drongo.address;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.protocol.ScriptType;

public class P2SHAddress extends Address {
    public P2SHAddress(byte[] scriptHash) {
        super(scriptHash);
    }

    public int getVersion() {
        return 5;
    }

    public ScriptType getScriptType() {
        return ScriptType.P2SH;
    }

    @Override
    public byte[] getOutputScriptData() {
        return hash;
    }

    @Override
    public String getOutputScriptDataType() {
        return "Script Hash";
    }

    public static P2SHAddress fromProgram(byte[] program) {
        return new P2SHAddress(Utils.sha256hash160(program));
    }
}
