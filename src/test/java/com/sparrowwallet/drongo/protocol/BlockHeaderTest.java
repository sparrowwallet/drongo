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
