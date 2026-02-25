package com.sparrowwallet.drongo.policy;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class MiniscriptTest {

    @Test
    public void testEqualsSameScript() {
        Miniscript a = new Miniscript("thresh(2,pk(key1),pk(key2),pk(key3))");
        Miniscript b = new Miniscript("thresh(2,pk(key1),pk(key2),pk(key3))");
        Assertions.assertEquals(a, b);
    }

    @Test
    public void testNotEqualsDifferentScript() {
        Miniscript a = new Miniscript("thresh(2,pk(key1),pk(key2),pk(key3))");
        Miniscript b = new Miniscript("thresh(3,pk(key1),pk(key2),pk(key3))");
        Assertions.assertNotEquals(a, b);
    }

    @Test
    public void testHashCodeConsistency() {
        Miniscript a = new Miniscript("thresh(2,pk(key1),pk(key2),pk(key3))");
        Miniscript b = new Miniscript("thresh(2,pk(key1),pk(key2),pk(key3))");
        Assertions.assertEquals(a.hashCode(), b.hashCode());
    }
}
