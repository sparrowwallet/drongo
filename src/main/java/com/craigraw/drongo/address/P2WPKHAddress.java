package com.craigraw.drongo.address;

import com.craigraw.drongo.protocol.Bech32;
import com.craigraw.drongo.protocol.Script;
import com.craigraw.drongo.protocol.ScriptChunk;

import java.util.ArrayList;
import java.util.List;

public class P2WPKHAddress extends Address {
    public static final String HRP = "bc";

    public P2WPKHAddress(byte[] pubKeyHash) {
        super(pubKeyHash);
    }

    public int getVersion() {
        return 0;
    }

    public String getAddress() {
        return Bech32.encode(HRP, getVersion(), pubKeyHash);
    }

    public Script getOutputScript() {
        List<ScriptChunk> chunks = new ArrayList<>();
        chunks.add(new ScriptChunk(Script.encodeToOpN(getVersion()), null));
        chunks.add(new ScriptChunk(pubKeyHash.length, pubKeyHash));

        return new Script(chunks);
    }
}
