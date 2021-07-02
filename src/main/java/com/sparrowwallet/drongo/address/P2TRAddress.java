package com.sparrowwallet.drongo.address;

import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.protocol.Bech32;
import com.sparrowwallet.drongo.protocol.Script;
import com.sparrowwallet.drongo.protocol.ScriptType;

public class P2TRAddress extends Address {
    private final byte[] pubKey;

    public P2TRAddress(byte[] pubKey) {
        super(Utils.sha256hash160(pubKey));
        this.pubKey = pubKey;
    }

    @Override
    public int getVersion(Network network) {
        return 1;
    }

    @Override
    public String getAddress(Network network) {
        return Bech32.encode(network.getBech32AddressHRP(), getVersion(), pubKey);
    }

    @Override
    public ScriptType getScriptType() {
        return ScriptType.P2TR;
    }

    @Override
    public Script getOutputScript() {
        return getScriptType().getOutputScript(pubKey);
    }

    @Override
    public byte[] getOutputScriptData() {
        return pubKey;
    }

    @Override
    public String getOutputScriptDataType() {
        return "Taproot";
    }
}
