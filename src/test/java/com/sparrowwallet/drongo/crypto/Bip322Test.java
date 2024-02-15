package com.sparrowwallet.drongo.crypto;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.address.Address;
import com.sparrowwallet.drongo.address.InvalidAddressException;
import com.sparrowwallet.drongo.protocol.ScriptType;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.SignatureException;

public class Bip322Test {
    @Test
    public void getBip322TaggedHash() {
        byte[] empty = Bip322.getBip322MessageHash("");
        Assertions.assertArrayEquals(Utils.hexToBytes("c90c269c4f8fcbe6880f72a721ddfbf1914268a794cbb21cfafee13770ae19f1"), empty);

        byte[] hello = Bip322.getBip322MessageHash("Hello World");
        Assertions.assertArrayEquals(Utils.hexToBytes("f0eb03b1a75ac6d9847f55c624a99169b5dccba2a31f5b23bea77ba270de0a7a"), hello);
    }

    @Test
    public void signMessageBip322() {
        ECKey privKey = DumpedPrivateKey.fromBase58("L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k").getKey();
        Address address = ScriptType.P2WPKH.getAddress(privKey);
        Assertions.assertEquals("bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l", address.toString());

        String signature = Bip322.signMessageBip322(ScriptType.P2WPKH, "", privKey);
        Assertions.assertEquals("AkcwRAIgM2gBAQqvZX15ZiysmKmQpDrG83avLIT492QBzLnQIxYCIBaTpOaD20qRlEylyxFSeEA2ba9YOixpX8z46TSDtS40ASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=", signature);

        String signature2 = Bip322.signMessageBip322(ScriptType.P2WPKH, "Hello World", privKey);
        Assertions.assertEquals("AkcwRAIgZRfIY3p7/DoVTty6YZbWS71bc5Vct9p9Fia83eRmw2QCICK/ENGfwLtptFluMGs2KsqoNSk89pO7F29zJLUx9a/sASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=", signature2);
    }

    @Test
    public void verifyMessageBip322Fail() throws InvalidAddressException, SignatureException {
        Address address = Address.fromString("bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l");
        String message1 = "";
        String signature2 = "AkcwRAIgZRfIY3p7/DoVTty6YZbWS71bc5Vct9p9Fia83eRmw2QCICK/ENGfwLtptFluMGs2KsqoNSk89pO7F29zJLUx9a/sASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=";

        Assertions.assertFalse(Bip322.verifyMessageBip322(ScriptType.P2WPKH, address, message1, signature2));
    }

    @Test
    public void verifyMessageBip322() throws InvalidAddressException, SignatureException {
        Address address = Address.fromString("bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l");
        String message1 = "";
        String signature1 = "AkcwRAIgM2gBAQqvZX15ZiysmKmQpDrG83avLIT492QBzLnQIxYCIBaTpOaD20qRlEylyxFSeEA2ba9YOixpX8z46TSDtS40ASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=";

        Assertions.assertTrue(Bip322.verifyMessageBip322(ScriptType.P2WPKH, address, message1, signature1));

        String message2 = "Hello World";
        String signature2 = "AkcwRAIgZRfIY3p7/DoVTty6YZbWS71bc5Vct9p9Fia83eRmw2QCICK/ENGfwLtptFluMGs2KsqoNSk89pO7F29zJLUx9a/sASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=";
        Assertions.assertTrue(Bip322.verifyMessageBip322(ScriptType.P2WPKH, address, message2, signature2));

        String signature3 = "AkgwRQIhAOzyynlqt93lOKJr+wmmxIens//zPzl9tqIOua93wO6MAiBi5n5EyAcPScOjf1lAqIUIQtr3zKNeavYabHyR8eGhowEhAsfxIAMZZEKUPYWI4BruhAQjzFT8FSFSajuFwrDL1Yhy";
        Assertions.assertTrue(Bip322.verifyMessageBip322(ScriptType.P2WPKH, address, message2, signature3));
    }

    @Test
    public void signMessageBip322Taproot() {
        ECKey privKey = DumpedPrivateKey.fromBase58("L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k").getKey();
        Address address = ScriptType.P2TR.getAddress(privKey);
        Assertions.assertEquals("bc1ppv609nr0vr25u07u95waq5lucwfm6tde4nydujnu8npg4q75mr5sxq8lt3", address.toString());

        String signature = Bip322.signMessageBip322(ScriptType.P2TR, "Hello World", privKey);
        Assertions.assertEquals("AUHd69PrJQEv+oKTfZ8l+WROBHuy9HKrbFCJu7U1iK2iiEy1vMU5EfMtjc+VSHM7aU0SDbak5IUZRVno2P5mjSafAQ==", signature);
    }

    @Test
    public void verifyMessageBip322Taproot() throws SignatureException {
        ECKey privKey = DumpedPrivateKey.fromBase58("L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k").getKey();
        Address address = ScriptType.P2TR.getAddress(privKey);
        Assertions.assertEquals("bc1ppv609nr0vr25u07u95waq5lucwfm6tde4nydujnu8npg4q75mr5sxq8lt3", address.toString());

        String message1 = "Hello World";
        String signature1 = "AUHd69PrJQEv+oKTfZ8l+WROBHuy9HKrbFCJu7U1iK2iiEy1vMU5EfMtjc+VSHM7aU0SDbak5IUZRVno2P5mjSafAQ==";

        Assertions.assertTrue(Bip322.verifyMessageBip322(ScriptType.P2TR, address, message1, signature1));
    }

    @Test
    public void signMessageBip322NestedSegwit() {
        ECKey privKey = DumpedPrivateKey.fromBase58("L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k").getKey();
        Address address = ScriptType.P2SH_P2WPKH.getAddress(privKey);
        Assertions.assertEquals("37qyp7jQAzqb2rCBpMvVtLDuuzKAUCVnJb", address.toString());

        Assertions.assertThrows(UnsupportedOperationException.class, () -> Bip322.signMessageBip322(ScriptType.P2SH_P2WPKH, "Hello World", privKey));
    }

    @Test
    public void verifyMessageBip322NestedSegwit() throws SignatureException {
        ECKey privKey = DumpedPrivateKey.fromBase58("L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k").getKey();
        Address address = ScriptType.P2SH_P2WPKH.getAddress(privKey);
        Assertions.assertEquals("37qyp7jQAzqb2rCBpMvVtLDuuzKAUCVnJb", address.toString());

        String message1 = "Hello World";
        String signature1 = "AkcwRAIgHx821fcP3D4R6RsXHF8kXza4d/SqpKGaGu++AEQjJz0CIH9cN5XGDkgkqqF9OMTbYvhgI7Yp9NoHXEgLstjqDOqDASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=";

        Assertions.assertThrows(UnsupportedOperationException.class, () -> Bip322.verifyMessageBip322(ScriptType.P2SH_P2WPKH, address, message1, signature1));
    }

    @Test
    public void verifyMessageBip322Multisig() throws SignatureException, InvalidAddressException {
        Address address = Address.fromString("bc1ppv609nr0vr25u07u95waq5lucwfm6tde4nydujnu8npg4q75mr5sxq8lt3");

        String message1 = "This will be a p2wsh 3-of-3 multisig BIP 322 signed message";
        String signature1 = "BQBIMEUCIQDQoXvGKLH58exuujBOta+7+GN7vi0lKwiQxzBpuNuXuAIgIE0XYQlFDOfxbegGYYzlf+tqegleAKE6SXYIa1U+uCcBRzBEAiATegywVl6GWrG9jJuPpNwtgHKyVYCX2yfuSSDRFATAaQIgTLlU6reLQsSIrQSF21z3PtUO2yAUseUWGZqRUIE7VKoBSDBFAiEAgxtpidsU0Z4u/+5RB9cyeQtoCW5NcreLJmWXZ8kXCZMCIBR1sXoEinhZE4CF9P9STGIcMvCuZjY6F5F0XTVLj9SjAWlTIQP3dyWvTZjUENWJowMWBsQrrXCUs20Gu5YF79CG5Ga0XSEDwqI5GVBOuFkFzQOGH5eTExSAj2Z/LDV/hbcvAPQdlJMhA17FuuJd+4wGuj+ZbVxEsFapTKAOwyhfw9qpch52JKxbU64=";

        Assertions.assertThrows(IllegalArgumentException.class, () -> Bip322.verifyMessageBip322(ScriptType.P2TR, address, message1, signature1));
    }
}
