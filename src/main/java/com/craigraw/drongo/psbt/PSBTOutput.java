package com.craigraw.drongo.psbt;

import com.craigraw.drongo.KeyDerivation;
import com.craigraw.drongo.crypto.LazyECPoint;
import com.craigraw.drongo.protocol.Script;

import java.util.LinkedHashMap;
import java.util.Map;

public class PSBTOutput {
    private Script redeemScript;
    private Script witnessScript;
    private Map<LazyECPoint, KeyDerivation> derivedPublicKeys = new LinkedHashMap<>();
    private Map<String, String> proprietary = new LinkedHashMap<>();

    public Script getRedeemScript() {
        return redeemScript;
    }

    public void setRedeemScript(Script redeemScript) {
        testIfNull(this.redeemScript);
        this.redeemScript = redeemScript;
    }

    public Script getWitnessScript() {
        return witnessScript;
    }

    public void setWitnessScript(Script witnessScript) {
        testIfNull(this.witnessScript);
        this.witnessScript = witnessScript;
    }

    public KeyDerivation getKeyDerivation(LazyECPoint publicKey) {
        return derivedPublicKeys.get(publicKey);
    }

    public void addDerivedPublicKey(LazyECPoint publicKey, KeyDerivation derivation) {
        if(derivedPublicKeys.containsKey(publicKey)) {
            throw new IllegalStateException("Duplicate public key in scope");
        }

        this.derivedPublicKeys.put(publicKey, derivation);
    }

    public void addProprietary(String key, String data) {
        proprietary.put(key, data);
    }

    private void testIfNull(Object obj) {
        if(obj != null) {
            throw new IllegalStateException("Duplicate keys in scope");
        }
    }
}
