package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.policy.Policy;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.ScriptType;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Locale;

public class PolicyTest {
    @Test
    public void testMiniscriptParsing() {
        Keystore keystore1 = new Keystore("Keystore 1");
        Keystore keystore2 = new Keystore("Keystore 2");
        Keystore keystore3 = new Keystore("Keystore 3");

        Policy policy = Policy.getPolicy(PolicyType.SINGLE_HD, ScriptType.P2PKH, List.of(keystore1), 1);
        Assertions.assertEquals("pkh(keystore1)", policy.getMiniscript().toString().toLowerCase(Locale.ROOT));
        Assertions.assertEquals(1, policy.getNumSignaturesRequired());

        Policy policy2 = Policy.getPolicy(PolicyType.SINGLE_HD, ScriptType.P2SH_P2WPKH, List.of(keystore1), 1);
        Assertions.assertEquals("sh(wpkh(keystore1))", policy2.getMiniscript().toString().toLowerCase(Locale.ROOT));
        Assertions.assertEquals(1, policy2.getNumSignaturesRequired());

        Policy policy3 = Policy.getPolicy(PolicyType.SINGLE_HD, ScriptType.P2WPKH, List.of(keystore1), 1);
        Assertions.assertEquals("wpkh(keystore1)", policy3.getMiniscript().toString().toLowerCase(Locale.ROOT));
        Assertions.assertEquals(1, policy3.getNumSignaturesRequired());

        Policy policy4 = Policy.getPolicy(PolicyType.MULTI_HD, ScriptType.P2SH, List.of(keystore1, keystore2, keystore3), 2);
        Assertions.assertEquals("sh(sortedmulti(2,keystore1,keystore2,keystore3))", policy4.getMiniscript().toString().toLowerCase(Locale.ROOT));
        Assertions.assertEquals(2, policy4.getNumSignaturesRequired());

        Policy policy5 = Policy.getPolicy(PolicyType.MULTI_HD, ScriptType.P2SH_P2WSH, List.of(keystore1, keystore2, keystore3), 2);
        Assertions.assertEquals("sh(wsh(sortedmulti(2,keystore1,keystore2,keystore3)))", policy5.getMiniscript().toString().toLowerCase(Locale.ROOT));
        Assertions.assertEquals(2, policy5.getNumSignaturesRequired());

        Policy policy6 = Policy.getPolicy(PolicyType.MULTI_HD, ScriptType.P2WSH, List.of(keystore1, keystore2, keystore3), 2);
        Assertions.assertEquals("wsh(sortedmulti(2,keystore1,keystore2,keystore3))", policy6.getMiniscript().toString().toLowerCase(Locale.ROOT));
        Assertions.assertEquals(2, policy6.getNumSignaturesRequired());
    }

    @Test
    public void testLabelsCannotAlterThreshold() {
        Keystore keystore1 = new Keystore("Keystore 1");
        Keystore keystore3 = new Keystore("Keystore 3");

        for(String label : List.of("pk(", "pkh(", "tr(", "sp(", "a pk( b", "multi(1", "Keystore,2")) {
            Policy policy = Policy.getPolicy(PolicyType.MULTI_HD, ScriptType.P2WSH, List.of(keystore1, new Keystore(label), keystore3), 2);
            Assertions.assertEquals(2, policy.getNumSignaturesRequired(), "Label \"" + label + "\" altered the threshold in " + policy.getMiniscript());
        }
    }

    @Test
    public void testNonLatinLabelsAreRetained() {
        Policy policy = Policy.getPolicy(PolicyType.MULTI_HD, ScriptType.P2WSH, List.of(new Keystore("\u041a\u043e\u0448\u0435\u043b\u0451\u043a"), new Keystore("\u79c1\u306e\u8ca1\u5e03"), new Keystore("Tr\u00e9zor")), 2);
        Assertions.assertEquals("wsh(sortedmulti(2,\u041a\u043e\u0448\u0435\u043b\u0451\u043a,\u79c1\u306e\u8ca1\u5e03,Tr\u00e9zor))", policy.getMiniscript().toString());
        Assertions.assertEquals(2, policy.getNumSignaturesRequired());
    }

    @Test
    public void testLabelsWithoutLettersOrDigitsFallBack() {
        Policy policy = Policy.getPolicy(PolicyType.MULTI_HD, ScriptType.P2WSH, List.of(new Keystore("\ud83d\udd11"), new Keystore("   "), new Keystore("Keystore 3")), 2);
        Assertions.assertEquals("wsh(sortedmulti(2,keystore,keystore,keystore3))", policy.getMiniscript().toString().toLowerCase(Locale.ROOT));
        Assertions.assertEquals(2, policy.getNumSignaturesRequired());
    }

    @Test
    public void testLabelsWithSeparatorsRetainThreshold() {
        Policy policy = Policy.getPolicy(PolicyType.MULTI_HD, ScriptType.P2WSH, List.of(new Keystore("Cold-card"), new Keystore("Trezor (2)"), new Keystore("Keystore 3")), 2);
        Assertions.assertEquals("wsh(sortedmulti(2,coldcard,trezor2,keystore3))", policy.getMiniscript().toString().toLowerCase(Locale.ROOT));
        Assertions.assertEquals(2, policy.getNumSignaturesRequired());

        Policy singlePolicy = Policy.getPolicy(PolicyType.SINGLE_HD, ScriptType.P2WPKH, List.of(new Keystore("Trezor (2)")), 1);
        Assertions.assertEquals("wpkh(trezor2)", singlePolicy.getMiniscript().toString().toLowerCase(Locale.ROOT));
        Assertions.assertEquals(1, singlePolicy.getNumSignaturesRequired());
    }
}
