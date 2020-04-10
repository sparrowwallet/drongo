package com.sparrowwallet.drongo.address;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.protocol.Script;
import com.sparrowwallet.drongo.protocol.ScriptChunk;
import com.sparrowwallet.drongo.protocol.ScriptOpCodes;

import java.util.ArrayList;
import java.util.List;

public class P2SHAddress extends Address {
    public P2SHAddress(byte[] scriptHash) {
        super(scriptHash);
    }

    public int getVersion() {
        return 5;
    }

    public Script getOutputScript() {
        List<ScriptChunk> chunks = new ArrayList<>();
        chunks.add(new ScriptChunk(ScriptOpCodes.OP_HASH160, null));
        chunks.add(new ScriptChunk(hash.length, hash));
        chunks.add(new ScriptChunk(ScriptOpCodes.OP_EQUAL, null));

        return new Script(chunks);
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
