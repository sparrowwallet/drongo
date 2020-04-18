package com.sparrowwallet.drongo.policy;

import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.wallet.Keystore;

import java.util.List;

import static com.sparrowwallet.drongo.protocol.ScriptType.*;
import static com.sparrowwallet.drongo.policy.PolicyType.*;

public class Policy {
    private static final String DEFAULT_NAME = "Default";

    private String name;
    private Miniscript miniscript;

    public Policy(Miniscript miniscript) {
        this(DEFAULT_NAME, miniscript);
    }

    public Policy(String name, Miniscript miniscript) {
        this.name = name;
        this.miniscript = miniscript;
    }

    public Miniscript getMiniscript() {
        return miniscript;
    }

    public void setMiniscript(Miniscript miniscript) {
        this.miniscript = miniscript;
    }

    public int getNumSignaturesRequired() {
        return getMiniscript().getNumSignaturesRequired();
    }

    public static Policy getPolicy(PolicyType policyType, ScriptType scriptType, List<Keystore> keystores, Integer threshold) {
        if(SINGLE.equals(policyType)) {
            if(P2PK.equals(scriptType)) {
                return new Policy(new Miniscript("pk(" + keystores.get(0).getScriptName() + ")"));
            }
            return new Policy(new Miniscript("pkh(" + keystores.get(0).getScriptName() + ")"));
        }

        if(MULTI.equals(policyType)) {
            StringBuilder builder = new StringBuilder("multi(");
            builder.append(threshold);
            for(Keystore keystore : keystores) {
                builder.append(",").append(keystore.getScriptName());
            }
            builder.append(")");
            return new Policy(new Miniscript(builder.toString()));
        }

        throw new PolicyException("No standard policy for " + policyType + " policy with script type " + scriptType);
    }
}
