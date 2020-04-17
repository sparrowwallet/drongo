package com.sparrowwallet.drongo.address;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.protocol.ScriptType;

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

    public ScriptType getScriptType() {
        return ScriptType.P2PK;
    }

    @Override
    public byte[] getOutputScriptData() {
        return pubKey;
    }

    @Override
    public String getOutputScriptDataType() {
        return "Public Key";
    }
}
