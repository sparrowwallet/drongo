package com.sparrowwallet.drongo.crypto;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.address.Address;
import com.sparrowwallet.drongo.address.InvalidAddressException;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.protocol.SigHash;
import com.sparrowwallet.drongo.protocol.TransactionSignature;
import com.sparrowwallet.drongo.psbt.PSBTInputSigner;
import org.junit.Assert;
import org.junit.Test;

import java.security.SignatureException;

public class Bip322Test {
    @Test
    public void getBip322TaggedHash() {
        byte[] empty = Bip322.getBip322MessageHash("");
        Assert.assertArrayEquals(Utils.hexToBytes("c90c269c4f8fcbe6880f72a721ddfbf1914268a794cbb21cfafee13770ae19f1"), empty);

        byte[] hello = Bip322.getBip322MessageHash("Hello World");
        Assert.assertArrayEquals(Utils.hexToBytes("f0eb03b1a75ac6d9847f55c624a99169b5dccba2a31f5b23bea77ba270de0a7a"), hello);
    }

    @Test
    public void signMessageBip322() {
        ECKey privKey = DumpedPrivateKey.fromBase58("L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k").getKey();
        Address address = ScriptType.P2WPKH.getAddress(privKey);
        Assert.assertEquals("bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l", address.toString());

        String signature = Bip322.signMessageBip322(address, "", new PSBTInputSigner() {
            @Override
            public TransactionSignature sign(Sha256Hash hash, SigHash sigHash, TransactionSignature.Type signatureType) {
                return privKey.sign(hash, sigHash, signatureType);
            }

            @Override
            public ECKey getPubKey() {
                return ECKey.fromPublicOnly(privKey);
            }
        });

        Assert.assertEquals("AkcwRAIgM2gBAQqvZX15ZiysmKmQpDrG83avLIT492QBzLnQIxYCIBaTpOaD20qRlEylyxFSeEA2ba9YOixpX8z46TSDtS40ASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=", signature);

        String signature2 = Bip322.signMessageBip322(address, "Hello World", new PSBTInputSigner() {
            @Override
            public TransactionSignature sign(Sha256Hash hash, SigHash sigHash, TransactionSignature.Type signatureType) {
                return privKey.sign(hash, sigHash, signatureType);
            }

            @Override
            public ECKey getPubKey() {
                return ECKey.fromPublicOnly(privKey);
            }
        });

        Assert.assertEquals("AkcwRAIgZRfIY3p7/DoVTty6YZbWS71bc5Vct9p9Fia83eRmw2QCICK/ENGfwLtptFluMGs2KsqoNSk89pO7F29zJLUx9a/sASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=", signature2);
    }

    @Test(expected = SignatureException.class)
    public void verifyMessageBip322Fail() throws InvalidAddressException, SignatureException {
        Address address = Address.fromString("bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l");
        String message1 = "";
        String signature2 = "AkcwRAIgZRfIY3p7/DoVTty6YZbWS71bc5Vct9p9Fia83eRmw2QCICK/ENGfwLtptFluMGs2KsqoNSk89pO7F29zJLUx9a/sASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=";

        Bip322.verifyMessageBip322(address, message1, signature2);
    }

    @Test
    public void verifyMessageBip322() throws InvalidAddressException, SignatureException {
        Address address = Address.fromString("bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l");
        String message1 = "";
        String signature1 = "AkcwRAIgM2gBAQqvZX15ZiysmKmQpDrG83avLIT492QBzLnQIxYCIBaTpOaD20qRlEylyxFSeEA2ba9YOixpX8z46TSDtS40ASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=";

        Bip322.verifyMessageBip322(address, message1, signature1);

        String message2 = "Hello World";
        String signature2 = "AkcwRAIgZRfIY3p7/DoVTty6YZbWS71bc5Vct9p9Fia83eRmw2QCICK/ENGfwLtptFluMGs2KsqoNSk89pO7F29zJLUx9a/sASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=";
        Bip322.verifyMessageBip322(address, message2, signature2);

        String signature3 = "AkgwRQIhAOzyynlqt93lOKJr+wmmxIens//zPzl9tqIOua93wO6MAiBi5n5EyAcPScOjf1lAqIUIQtr3zKNeavYabHyR8eGhowEhAsfxIAMZZEKUPYWI4BruhAQjzFT8FSFSajuFwrDL1Yhy";
        Bip322.verifyMessageBip322(address, message2, signature3);
    }

    @Test
    public void signMessageBip322Taproot() {
        ECKey privKey = DumpedPrivateKey.fromBase58("L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k").getKey();
        Address address = ScriptType.P2TR.getAddress(privKey);
        Assert.assertEquals("bc1ppv609nr0vr25u07u95waq5lucwfm6tde4nydujnu8npg4q75mr5sxq8lt3", address.toString());

        String signature = Bip322.signMessageBip322(address, "Hello World", new PSBTInputSigner() {
            @Override
            public TransactionSignature sign(Sha256Hash hash, SigHash sigHash, TransactionSignature.Type signatureType) {
                return address.getScriptType().getOutputKey(privKey).sign(hash, sigHash, signatureType);
            }

            @Override
            public ECKey getPubKey() {
                return ECKey.fromPublicOnly(privKey);
            }
        });

        Assert.assertEquals("AUHd69PrJQEv+oKTfZ8l+WROBHuy9HKrbFCJu7U1iK2iiEy1vMU5EfMtjc+VSHM7aU0SDbak5IUZRVno2P5mjSafAQ==", signature);
    }

    @Test
    public void verifyMessageBip322Taproot() throws SignatureException {
        ECKey privKey = DumpedPrivateKey.fromBase58("L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k").getKey();
        Address address = ScriptType.P2TR.getAddress(privKey);
        Assert.assertEquals("bc1ppv609nr0vr25u07u95waq5lucwfm6tde4nydujnu8npg4q75mr5sxq8lt3", address.toString());

        String message1 = "Hello World";
        String signature1 = "AUHd69PrJQEv+oKTfZ8l+WROBHuy9HKrbFCJu7U1iK2iiEy1vMU5EfMtjc+VSHM7aU0SDbak5IUZRVno2P5mjSafAQ==";

        Bip322.verifyMessageBip322(address, message1, signature1);
    }
}
