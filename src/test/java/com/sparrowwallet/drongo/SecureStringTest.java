package com.sparrowwallet.drongo;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class SecureStringTest {
    @Test
    public void subSequence() {
        String value = "abcdef";
        SecureString secureString = new SecureString(value);
        for(int start = 0; start <= value.length(); start++) {
            for(int end = start; end <= value.length(); end++) {
                SecureString sub = (SecureString)secureString.subSequence(start, end);
                Assertions.assertEquals(value.substring(start, end), sub.asString());
            }
        }

        Assertions.assertEquals("cd", ((SecureString)secureString.subSequence(1, 5).subSequence(1, 3)).asString());
    }

    @Test
    public void subSequenceOutOfBounds() {
        SecureString secureString = new SecureString("abcdef");
        Assertions.assertThrows(IndexOutOfBoundsException.class, () -> secureString.subSequence(-1, 2));
        Assertions.assertThrows(IndexOutOfBoundsException.class, () -> secureString.subSequence(4, 2));
        Assertions.assertThrows(IndexOutOfBoundsException.class, () -> secureString.subSequence(2, 7));
    }
}
