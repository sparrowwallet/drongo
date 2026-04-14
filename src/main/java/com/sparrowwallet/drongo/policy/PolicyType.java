package com.sparrowwallet.drongo.policy;

import com.sparrowwallet.drongo.protocol.ScriptType;

import static com.sparrowwallet.drongo.protocol.ScriptType.*;

public enum PolicyType {
    SINGLE_HD("Single Signature HD", "Single Signature HD", P2WPKH), MULTI_HD("Multi Signature HD", "Multi Signature HD", P2WSH), SINGLE_SP("Single Signature SP", "Single Signature SP (Silent Payments)", P2TR);

    private final String name;
    private final String description;
    private final ScriptType defaultScriptType;

    PolicyType(String name, String description, ScriptType defaultScriptType) {
        this.name = name;
        this.description = description;
        this.defaultScriptType = defaultScriptType;
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    public ScriptType getDefaultScriptType() {
        return defaultScriptType;
    }

    @Override
    public String toString() {
        return name;
    }
}
