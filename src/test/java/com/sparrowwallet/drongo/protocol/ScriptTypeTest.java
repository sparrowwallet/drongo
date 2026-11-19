package com.sparrowwallet.drongo.protocol;

import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.policy.PolicyType;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class ScriptTypeTest {
    @AfterEach
    public void tearDown() {
        Network.set(null);
    }

    @Test
    public void silentPaymentsPolicyDefaultsToBip352Derivation() {
        Network.set(Network.MAINNET);
        Assertions.assertEquals("m/352'/0'/0'", ScriptType.P2TR.getDefaultDerivationPath(PolicyType.SINGLE_SP));
        Assertions.assertEquals(KeyDerivation.parsePath("m/352'/0'/0'"), ScriptType.P2TR.getDefaultDerivation(PolicyType.SINGLE_SP));
        Assertions.assertEquals(KeyDerivation.parsePath("m/352'/0'/2'"), ScriptType.P2TR.getDefaultDerivation(PolicyType.SINGLE_SP, 2));

        Network.set(Network.TESTNET);
        Assertions.assertEquals("m/352'/1'/0'", ScriptType.P2TR.getDefaultDerivationPath(PolicyType.SINGLE_SP));
    }

    @Test
    public void otherPoliciesKeepTheScriptTypeDefault() {
        Network.set(Network.MAINNET);
        Assertions.assertEquals(ScriptType.P2TR.getDefaultDerivationPath(), ScriptType.P2TR.getDefaultDerivationPath(PolicyType.SINGLE_HD));
        Assertions.assertEquals(ScriptType.P2TR.getDefaultDerivation(), ScriptType.P2TR.getDefaultDerivation(PolicyType.SINGLE_HD));
        Assertions.assertEquals(ScriptType.P2WSH.getDefaultDerivation(3), ScriptType.P2WSH.getDefaultDerivation(PolicyType.MULTI_HD, 3));
        Assertions.assertEquals(ScriptType.P2WPKH.getDefaultDerivation(), ScriptType.P2WPKH.getDefaultDerivation(null));
    }
}
