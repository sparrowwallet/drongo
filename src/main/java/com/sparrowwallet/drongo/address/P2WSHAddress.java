package com.sparrowwallet.drongo.address;

import com.sparrowwallet.drongo.protocol.*;

import java.util.ArrayList;
import java.util.List;

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

    public Script getOutputScript() {
        List<ScriptChunk> chunks = new ArrayList<>();
        chunks.add(new ScriptChunk(Script.encodeToOpN(getVersion()), null));
        chunks.add(new ScriptChunk(hash.length, hash));

        return new Script(chunks);
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
