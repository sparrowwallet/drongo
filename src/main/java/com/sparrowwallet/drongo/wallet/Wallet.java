package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.ScriptType;

import java.util.ArrayList;
import java.util.List;

public class Wallet {
    private PolicyType policyType;
    private ScriptType scriptType;
    private String policy;
    private List<Keystore> keystores = new ArrayList<>();

    public PolicyType getPolicyType() {
        return policyType;
    }

    public void setPolicyType(PolicyType policyType) {
        this.policyType = policyType;
    }

    public ScriptType getScriptType() {
        return scriptType;
    }

    public void setScriptType(ScriptType scriptType) {
        this.scriptType = scriptType;
    }

    public String getPolicy() {
        return policy;
    }

    public void setPolicy(String policy) {
        this.policy = policy;
    }

    public List<Keystore> getKeystores() {
        return keystores;
    }

    public void setKeystores(List<Keystore> keystores) {
        this.keystores = keystores;
    }
}
