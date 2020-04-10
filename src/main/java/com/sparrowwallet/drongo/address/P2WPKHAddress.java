package com.sparrowwallet.drongo.address;

import com.sparrowwallet.drongo.protocol.Bech32;
import com.sparrowwallet.drongo.protocol.Script;
import com.sparrowwallet.drongo.protocol.ScriptChunk;

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
        return "Witness Public Key Hash";
    }
}
