package com.craigraw.drongo.address;

import com.craigraw.drongo.protocol.*;

import java.util.ArrayList;
import java.util.List;

import static com.craigraw.drongo.address.P2WPKHAddress.HRP;

public class P2WSHAddress extends Address {
    public P2WSHAddress(byte[] pubKeyHash) {
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

    public static P2WSHAddress fromProgram(byte[] program) {
        return new P2WSHAddress(Sha256Hash.hash(program));
    }
}
