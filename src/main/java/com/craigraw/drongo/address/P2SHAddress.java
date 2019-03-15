package com.craigraw.drongo.address;

import com.craigraw.drongo.Utils;
import com.craigraw.drongo.protocol.Script;
import com.craigraw.drongo.protocol.ScriptChunk;
import com.craigraw.drongo.protocol.ScriptOpCodes;

import java.util.ArrayList;
import java.util.List;

public class P2SHAddress extends Address {
    public P2SHAddress(byte[] pubKeyHash) {
        super(pubKeyHash);
    }

    public int getVersion() {
        return 5;
    }

    public Script getOutputScript() {
        List<ScriptChunk> chunks = new ArrayList<>();
        chunks.add(new ScriptChunk(ScriptOpCodes.OP_HASH160, null));
        chunks.add(new ScriptChunk(pubKeyHash.length, pubKeyHash));
        chunks.add(new ScriptChunk(ScriptOpCodes.OP_EQUAL, null));

        return new Script(chunks);
    }

    public static P2SHAddress fromProgram(byte[] program) {
        return new P2SHAddress(Utils.sha256hash160(program));
    }
}
