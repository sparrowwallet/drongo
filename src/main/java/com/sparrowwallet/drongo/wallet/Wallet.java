package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.crypto.KeyCrypter;
import com.sparrowwallet.drongo.crypto.ScryptKeyCrypter;
import com.sparrowwallet.drongo.policy.Policy;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.ScriptType;
import org.bouncycastle.crypto.params.KeyParameter;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class Wallet {

    private String name;
    private PolicyType policyType;
    private ScriptType scriptType;
    private Policy defaultPolicy;
    private List<Keystore> keystores = new ArrayList<>();

    public Wallet() {
    }

    public Wallet(String name) {
        this.name = name;
    }

    public Wallet(String name, PolicyType policyType, ScriptType scriptType) {
        this.name = name;
        this.policyType = policyType;
        this.scriptType = scriptType;
        this.keystores = Collections.singletonList(new Keystore());
        this.defaultPolicy = Policy.getPolicy(policyType, scriptType, keystores, null);
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

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

    public Policy getDefaultPolicy() {
        return defaultPolicy;
    }

    public void setDefaultPolicy(Policy defaultPolicy) {
        this.defaultPolicy = defaultPolicy;
    }

    public List<Keystore> getKeystores() {
        return keystores;
    }

    public void setKeystores(List<Keystore> keystores) {
        this.keystores = keystores;
    }

    public boolean isValid() {
        if(policyType == null || scriptType == null || defaultPolicy == null || keystores.isEmpty()) {
            return false;
        }

        if(!ScriptType.getScriptTypesForPolicyType(policyType).contains(scriptType)) {
            return false;
        }

        int numSigs;
        try {
            numSigs = defaultPolicy.getNumSignaturesRequired();
        } catch (Exception e) {
            return false;
        }

        if(policyType.equals(PolicyType.SINGLE) && (numSigs != 1 || keystores.size() != 1)) {
            return false;
        }

        if(policyType.equals(PolicyType.MULTI) && (numSigs <= 1 || numSigs > keystores.size())) {
            return false;
        }

        for(Keystore keystore : keystores) {
            if(!keystore.isValid()) {
                return false;
            }
            if(derivationMatchesAnotherScriptType(keystore.getKeyDerivation().getDerivationPath())) {
                return false;
            }
        }

        return true;
    }

    public boolean derivationMatchesAnotherScriptType(String derivationPath) {
        if(scriptType != null && scriptType.getAccount(derivationPath) > -1) {
            return false;
        }

        return Arrays.stream(ScriptType.values()).anyMatch(scriptType -> !scriptType.equals(this.scriptType) && scriptType.getAccount(derivationPath) > -1);
    }

    public Wallet copy() {
        Wallet copy = new Wallet(name);
        copy.setPolicyType(policyType);
        copy.setScriptType(scriptType);
        copy.setDefaultPolicy(defaultPolicy.copy());
        for(Keystore keystore : keystores) {
            copy.getKeystores().add(keystore.copy());
        }
        return copy;
    }

    public boolean isEncrypted() {
        for(Keystore keystore : keystores) {
            if(keystore.isEncrypted()) {
                return true;
            }
        }

        return false;
    }

    public void encrypt(String password) {
        KeyCrypter keyCrypter = new ScryptKeyCrypter();
        KeyParameter key = keyCrypter.deriveKey(password);
        for(Keystore keystore : keystores) {
            keystore.encrypt(keyCrypter, key);
        }
    }

    public void decrypt(String password, String passphrase) {
        KeyCrypter keyCrypter = new ScryptKeyCrypter();
        KeyParameter key = keyCrypter.deriveKey(password);
        for(Keystore keystore : keystores) {
            keystore.decrypt(keyCrypter, passphrase, key);
        }
    }
}
