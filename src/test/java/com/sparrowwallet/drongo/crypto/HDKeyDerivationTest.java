package com.sparrowwallet.drongo.crypto;

import com.sparrowwallet.drongo.Utils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

public class HDKeyDerivationTest {
    private static final byte[] CHAIN_CODE = Utils.hexToBytes("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508");

    @Test
    public void testMasterPrivKeyEqualToCurveOrderRejected() {
        byte[] privKeyBytes = Utils.bigIntegerToBytes(ECKey.CURVE.getN(), 32);
        Assertions.assertThrows(HDDerivationException.class, () -> HDKeyDerivation.createMasterPrivKeyFromBytes(privKeyBytes, CHAIN_CODE));
    }

    @Test
    public void testMasterPrivKeyGreaterThanCurveOrderRejected() {
        byte[] privKeyBytes = Utils.bigIntegerToBytes(ECKey.CURVE.getN().add(BigInteger.ONE), 32);
        Assertions.assertThrows(HDDerivationException.class, () -> HDKeyDerivation.createMasterPrivKeyFromBytes(privKeyBytes, CHAIN_CODE));
    }

    @Test
    public void testMasterPrivKeyZeroRejected() {
        byte[] privKeyBytes = new byte[32];
        Assertions.assertThrows(HDDerivationException.class, () -> HDKeyDerivation.createMasterPrivKeyFromBytes(privKeyBytes, CHAIN_CODE));
    }

    @Test
    public void testMasterPrivKeyOneLessThanCurveOrderAccepted() {
        byte[] privKeyBytes = Utils.bigIntegerToBytes(ECKey.CURVE.getN().subtract(BigInteger.ONE), 32);
        DeterministicKey masterKey = HDKeyDerivation.createMasterPrivKeyFromBytes(privKeyBytes, CHAIN_CODE);
        Assertions.assertEquals(ECKey.CURVE.getN().subtract(BigInteger.ONE), masterKey.getPrivKey());
        Assertions.assertEquals(33, masterKey.getPubKey().length);
    }

    @Test
    public void testBip32Vector1() {
        byte[] seed = Utils.hexToBytes("000102030405060708090a0b0c0d0e0f");
        DeterministicKey masterKey = HDKeyDerivation.createMasterPrivateKey(seed);
        Assertions.assertEquals("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35", Utils.bytesToHex(masterKey.getPrivKeyBytes()));

        DeterministicKey child = HDKeyDerivation.deriveChildKey(masterKey, new ChildNumber(0, true));
        Assertions.assertEquals("edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea", Utils.bytesToHex(child.getPrivKeyBytes()));
    }
}
