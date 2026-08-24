package com.sparrowwallet.drongo.protocol;

import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.Utils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

public class BlockHeaderTest {
    public static final String GENESIS_HEADER_HEX = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c";
    public static final String BLOCK_800000_HEADER_HEX = "00601d3455bb9fbd966b3ea2dc42d0c22722e4c0c1729fad17210100000000000000000055087fab0c8f3f89f8bcfd4df26c504d81b0a88e04907161838c0c53001af09135edbd64943805175e955e06";

    @Test
    public void testDecodeCompactBits() {
        Assertions.assertEquals(new BigInteger("ffff", 16).shiftLeft(208), Utils.decodeCompactBits(0x1d00ffffL));
        Assertions.assertEquals(new BigInteger("053894", 16).shiftLeft(160), Utils.decodeCompactBits(0x17053894L));
        Assertions.assertEquals(BigInteger.valueOf(0x123456), Utils.decodeCompactBits(0x03123456L));
        Assertions.assertEquals(BigInteger.valueOf(0x1234), Utils.decodeCompactBits(0x02123456L));
        Assertions.assertTrue(Utils.decodeCompactBits(0x1d80ffffL).signum() < 0);
    }

    @Test
    public void testEncodeCompactBits() {
        //Bitcoin Core's arith_uint256 round trip vectors, as lifted by Electrum: the compact form a target encodes back to is not always the one it decoded from
        Assertions.assertEquals(0x00000000L, Utils.encodeCompactBits(Utils.decodeCompactBits(0x00123456L)));
        Assertions.assertEquals(0x00000000L, Utils.encodeCompactBits(Utils.decodeCompactBits(0x01003456L)));
        Assertions.assertEquals(0x00000000L, Utils.encodeCompactBits(Utils.decodeCompactBits(0x02000056L)));
        Assertions.assertEquals(0x00000000L, Utils.encodeCompactBits(Utils.decodeCompactBits(0x03000000L)));
        Assertions.assertEquals(0x00000000L, Utils.encodeCompactBits(Utils.decodeCompactBits(0x04000000L)));
        Assertions.assertEquals(0x01120000L, Utils.encodeCompactBits(Utils.decodeCompactBits(0x01123456L)));
        Assertions.assertEquals(0x02123400L, Utils.encodeCompactBits(Utils.decodeCompactBits(0x02123456L)));
        Assertions.assertEquals(0x03123456L, Utils.encodeCompactBits(Utils.decodeCompactBits(0x03123456L)));
        Assertions.assertEquals(0x04123456L, Utils.encodeCompactBits(Utils.decodeCompactBits(0x04123456L)));
        Assertions.assertEquals(0x05009234L, Utils.encodeCompactBits(Utils.decodeCompactBits(0x05009234L)));
        Assertions.assertEquals(0x20123456L, Utils.encodeCompactBits(Utils.decodeCompactBits(0x20123456L)));
        Assertions.assertEquals(0x05123456L, Utils.encodeCompactBits(new BigInteger("1234560000", 16)));
        Assertions.assertEquals(0x0600c0deL, Utils.encodeCompactBits(new BigInteger("c0de000000", 16)));

        //A mantissa whose top bit is set must not be encoded as the negative flag
        Assertions.assertEquals(0x02008000L, Utils.encodeCompactBits(BigInteger.valueOf(0x80)));
        Assertions.assertEquals(0x00000000L, Utils.encodeCompactBits(BigInteger.ZERO));

        //decodeCompactBits returns a negative value for the compact forms that set the sign bit, which are not encodable difficulty targets
        Assertions.assertThrows(IllegalArgumentException.class, () -> Utils.encodeCompactBits(Utils.decodeCompactBits(0x1d80ffffL)));

        //The consensus targets of every network Sparrow supports round trip unchanged
        Assertions.assertEquals(0x1d00ffffL, Utils.encodeCompactBits(Utils.decodeCompactBits(0x1d00ffffL)));
        Assertions.assertEquals(0x207fffffL, Utils.encodeCompactBits(Utils.decodeCompactBits(0x207fffffL)));
        Assertions.assertEquals(0x1e0377aeL, Utils.encodeCompactBits(Utils.decodeCompactBits(0x1e0377aeL)));
        Assertions.assertEquals(0x17053894L, Utils.encodeCompactBits(Utils.decodeCompactBits(0x17053894L)));
    }

    @Test
    public void testGenesisHeader() {
        Network.set(Network.MAINNET);

        BlockHeader blockHeader = new BlockHeader(Utils.hexToBytes(GENESIS_HEADER_HEX));
        Assertions.assertEquals("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f", blockHeader.getHash().toString());
        Assertions.assertEquals(0x1d00ffffL, blockHeader.getDifficultyTarget());
        Assertions.assertTrue(blockHeader.verifyProofOfWork());
    }

    @Test
    public void testBlock800000Header() {
        Network.set(Network.MAINNET);

        BlockHeader blockHeader = new BlockHeader(Utils.hexToBytes(BLOCK_800000_HEADER_HEX));
        Assertions.assertEquals("00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a054", blockHeader.getHash().toString());
        Assertions.assertEquals(0x17053894L, blockHeader.getDifficultyTarget());
        Assertions.assertTrue(blockHeader.verifyProofOfWork());
    }

    @Test
    public void testTamperedHeaderFailsProofOfWork() {
        Network.set(Network.MAINNET);

        byte[] tampered = Utils.hexToBytes(BLOCK_800000_HEADER_HEX);
        tampered[79] ^= 0x01;
        BlockHeader blockHeader = new BlockHeader(tampered);
        Assertions.assertFalse(blockHeader.verifyProofOfWork());
    }

    @Test
    public void testTargetAboveProofOfWorkLimitFails() {
        Network.set(Network.MAINNET);

        //An absurdly easy target above the mainnet powLimit must fail regardless of the header hash
        BlockHeader genesis = new BlockHeader(Utils.hexToBytes(GENESIS_HEADER_HEX));
        BlockHeader blockHeader = new BlockHeader(genesis.getVersion(), genesis.getPrevBlockHash(), genesis.getMerkleRoot(), null, genesis.getTime(), 0x2100ffffL, genesis.getNonce());
        Assertions.assertFalse(blockHeader.verifyProofOfWork());
    }

    @AfterEach
    public void tearDown() throws Exception {
        Network.set(null);
    }
}
