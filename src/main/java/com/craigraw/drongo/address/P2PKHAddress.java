package com.craigraw.drongo.address;

import com.craigraw.drongo.protocol.Script;
import com.craigraw.drongo.protocol.ScriptChunk;
import com.craigraw.drongo.protocol.ScriptOpCodes;

import java.util.ArrayList;
import java.util.List;

public class P2PKHAddress extends Address {
    public P2PKHAddress(byte[] pubKeyHash) {
        super(pubKeyHash);
    }

    public int getVersion() {
        return 0;
    }

    public Script getOutputScript() {
        List<ScriptChunk> chunks = new ArrayList<>();
        chunks.add(new ScriptChunk(ScriptOpCodes.OP_DUP, null));
        chunks.add(new ScriptChunk(ScriptOpCodes.OP_HASH160, null));
        chunks.add(new ScriptChunk(pubKeyHash.length, pubKeyHash));
        chunks.add(new ScriptChunk(ScriptOpCodes.OP_EQUALVERIFY, null));
        chunks.add(new ScriptChunk(ScriptOpCodes.OP_CHECKSIG, null));

        return new Script(chunks);
    }
}
