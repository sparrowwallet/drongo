package com.sparrowwallet.drongo.policy;

import com.sparrowwallet.drongo.protocol.ScriptType;

import static com.sparrowwallet.drongo.protocol.ScriptType.*;
import static com.sparrowwallet.drongo.policy.PolicyType.*;

public class Policy {
    private String policy;

    public Policy(String policy) {
        this.policy = policy;
    }

    public String getPolicy() {
        return policy;
    }

    public void setPolicy(String policy) {
        this.policy = policy;
    }

    public static Policy getPolicy(PolicyType policyType, ScriptType scriptType, Integer threshold, Integer numCosigners) {
        if(SINGLE.equals(policyType)) {
            if(P2PK.equals(scriptType)) {
                return new Policy("pk(<key1>)");
            }
            return new Policy("pkh(<key1>)");
        }

        if(MULTI.equals(policyType)) {
            return new Policy("multi(<threshold>,<key1>,<key2>)");
        }

        throw new PolicyException("No standard policy for " + policyType + " policy with script type " + scriptType);
    }
}
