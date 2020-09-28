package com.sparrowwallet.drongo.address;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.protocol.Network;
import com.sparrowwallet.drongo.protocol.Script;
import com.sparrowwallet.drongo.protocol.ScriptType;

public class P2PKAddress extends Address {
    private byte[] pubKey;

    public P2PKAddress(Network network, byte[] pubKey) {
        super(network, Utils.sha256hash160(pubKey));
        this.pubKey = pubKey;
    }

    public int getVersion() {
        return network.pkhVersion;
    }

    public ScriptType getScriptType() {
        return ScriptType.P2PK;
    }

    public Script getOutputScript() {
        return getScriptType().getOutputScript(pubKey);
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
