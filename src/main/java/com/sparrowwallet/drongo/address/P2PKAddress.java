package com.sparrowwallet.drongo.address;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.protocol.Script;
import com.sparrowwallet.drongo.protocol.ScriptChunk;
import com.sparrowwallet.drongo.protocol.ScriptOpCodes;

import java.util.ArrayList;
import java.util.List;

public class P2PKAddress extends Address {
    private byte[] pubKey;

    public P2PKAddress(byte[] pubKey) {
        super(Utils.sha256hash160(pubKey));
        this.pubKey = pubKey;
    }

    public int getVersion() {
        return 0;
    }

    public Script getOutputScript() {
        List<ScriptChunk> chunks = new ArrayList<>();
        chunks.add(new ScriptChunk(pubKey.length, pubKey));
        chunks.add(new ScriptChunk(ScriptOpCodes.OP_CHECKSIG, null));

        return new Script(chunks);
    }
}
