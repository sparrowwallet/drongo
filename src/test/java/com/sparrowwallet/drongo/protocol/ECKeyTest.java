package com.sparrowwallet.drongo.protocol;

import com.sparrowwallet.drongo.crypto.ECKey;
import org.junit.Assert;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

public class ECKeyTest {
    @Test
    public void encryptDecrypt() {
        String testMessage = "thisisatestmessage";
        ECKey pubKey = ECKey.createKeyPbkdf2HmacSha512("iampassword");
        byte[] encrypted = pubKey.encryptEcies(testMessage.getBytes(StandardCharsets.UTF_8), "BIE1".getBytes(StandardCharsets.UTF_8));

        byte[] decrypted = pubKey.decryptEcies(encrypted, "BIE1".getBytes(StandardCharsets.UTF_8));
        String decStr = new String(decrypted, StandardCharsets.UTF_8);
        Assert.assertEquals(testMessage, decStr);
    }
}
