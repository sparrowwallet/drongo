package com.sparrowwallet.drongo.address;

import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.protocol.Script;
import com.sparrowwallet.drongo.protocol.ScriptType;

public class P2PKAddress extends Address {
    private byte[] pubKey;

    public P2PKAddress(byte[] pubKey) {
        super(Utils.sha256hash160(pubKey));
        this.pubKey = pubKey;
    }

    @Override
    public int getVersion(Network network) {
        return network.getP2PKHAddressHeader();
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
