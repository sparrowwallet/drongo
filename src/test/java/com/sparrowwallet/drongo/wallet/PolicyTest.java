package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.policy.Policy;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.ScriptType;
import org.junit.Assert;
import org.junit.Test;

import java.util.List;
import java.util.Locale;

public class PolicyTest {
    @Test
    public void testMiniscriptParsing() {
        Keystore keystore1 = new Keystore("Keystore 1");
        Keystore keystore2 = new Keystore("Keystore 2");
        Keystore keystore3 = new Keystore("Keystore 3");

        Policy policy = Policy.getPolicy(PolicyType.SINGLE, ScriptType.P2PKH, List.of(keystore1), 1);
        Assert.assertEquals("pkh(keystore1)", policy.getMiniscript().toString().toLowerCase(Locale.ROOT));
        Assert.assertEquals(1, policy.getNumSignaturesRequired());

        Policy policy2 = Policy.getPolicy(PolicyType.SINGLE, ScriptType.P2SH_P2WPKH, List.of(keystore1), 1);
        Assert.assertEquals("sh(wpkh(keystore1))", policy2.getMiniscript().toString().toLowerCase(Locale.ROOT));
        Assert.assertEquals(1, policy2.getNumSignaturesRequired());

        Policy policy3 = Policy.getPolicy(PolicyType.SINGLE, ScriptType.P2WPKH, List.of(keystore1), 1);
        Assert.assertEquals("wpkh(keystore1)", policy3.getMiniscript().toString().toLowerCase(Locale.ROOT));
        Assert.assertEquals(1, policy3.getNumSignaturesRequired());

        Policy policy4 = Policy.getPolicy(PolicyType.MULTI, ScriptType.P2SH, List.of(keystore1, keystore2, keystore3), 2);
        Assert.assertEquals("sh(sortedmulti(2,keystore1,keystore2,keystore3))", policy4.getMiniscript().toString().toLowerCase(Locale.ROOT));
        Assert.assertEquals(2, policy4.getNumSignaturesRequired());

        Policy policy5 = Policy.getPolicy(PolicyType.MULTI, ScriptType.P2SH_P2WSH, List.of(keystore1, keystore2, keystore3), 2);
        Assert.assertEquals("sh(wsh(sortedmulti(2,keystore1,keystore2,keystore3)))", policy5.getMiniscript().toString().toLowerCase(Locale.ROOT));
        Assert.assertEquals(2, policy5.getNumSignaturesRequired());

        Policy policy6 = Policy.getPolicy(PolicyType.MULTI, ScriptType.P2WSH, List.of(keystore1, keystore2, keystore3), 2);
        Assert.assertEquals("wsh(sortedmulti(2,keystore1,keystore2,keystore3))", policy6.getMiniscript().toString().toLowerCase(Locale.ROOT));
        Assert.assertEquals(2, policy6.getNumSignaturesRequired());
    }
}
