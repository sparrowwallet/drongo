package com.sparrowwallet.drongo.protocol;

import com.sparrowwallet.drongo.Network;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class HeaderCheckpointsTest {
    //Mainnet block 2015, the last header of the first difficulty period, whose period and the one after it are both at minimum difficulty
    private static final String MAINNET_FIRST_PIN = "00000000693067b0e6b440bc51450b9f3850561b07f6d3c021c54fbd6abb9763";
    private static final String MAINNET_SECOND_PIN = "00000000f037ad09d0b05ee66b8c1da83030abaf909d2b1bf519c3c7d2cd3fdf";
    //Mainnet block 32255, the last header of the period before the chain's first difficulty rise
    private static final int MAINNET_FIRST_RISE_HEIGHT = 32255;
    private static final long MAINNET_FIRST_RISE_BITS = 0x1d00d86aL;

    @Test
    public void testMainnetCheckpoints() {
        HeaderCheckpoints checkpoints = Network.MAINNET.getHeaderCheckpoints();
        Assertions.assertEquals(MAINNET_FIRST_PIN, checkpoints.getHash(2015).toString());
        Assertions.assertEquals(MAINNET_SECOND_PIN, checkpoints.getHash(4031).toString());
        Assertions.assertEquals(0x1d00ffffL, checkpoints.getBitsAfter(2015));
        Assertions.assertEquals(MAINNET_FIRST_RISE_BITS, checkpoints.getBitsAfter(MAINNET_FIRST_RISE_HEIGHT));
        Assertions.assertEquals(0, (checkpoints.getMaxHeight() + 1) % HeaderChainState.RETARGET_INTERVAL);
        Assertions.assertTrue(checkpoints.getMaxHeight() > 950000, "Mainnet checkpoints end at " + checkpoints.getMaxHeight());
    }

    @Test
    public void testEveryNetworkResourceParses() {
        for(Network network : Network.values()) {
            HeaderCheckpoints checkpoints = network.getHeaderCheckpoints();
            int maxHeight = checkpoints.getMaxHeight();
            //Every pinned height is the last of a difficulty period, except regtest's genesis anchor
            Assertions.assertEquals(network == Network.REGTEST ? 1 : 0, (maxHeight + 1) % HeaderChainState.RETARGET_INTERVAL, network.getName());
            Assertions.assertDoesNotThrow(() -> checkpoints.getHash(maxHeight), network.getName());
            Assertions.assertDoesNotThrow(() -> checkpoints.getBitsAfter(maxHeight), network.getName());
        }
    }

    @Test
    public void testEveryNetworkChainStateAnchorsAtTheLastPin() {
        for(Network network : Network.values()) {
            HeaderCheckpoints checkpoints = network.getHeaderCheckpoints();
            HeaderChainState chainState = checkpoints.newChainState();
            Assertions.assertEquals(checkpoints.getMaxHeight(), chainState.getHeight(), network.getName());
            Assertions.assertEquals(checkpoints.getHash(checkpoints.getMaxHeight()), chainState.getHash(), network.getName());
        }
    }

    @Test
    public void testPinnedHeightAtOrAbove() {
        HeaderCheckpoints checkpoints = Network.MAINNET.getHeaderCheckpoints();
        Assertions.assertEquals(2015, checkpoints.getPinnedHeightAtOrAbove(0));
        Assertions.assertEquals(2015, checkpoints.getPinnedHeightAtOrAbove(1));
        Assertions.assertEquals(2015, checkpoints.getPinnedHeightAtOrAbove(2015));
        Assertions.assertEquals(4031, checkpoints.getPinnedHeightAtOrAbove(2016));
        Assertions.assertEquals(4031, checkpoints.getPinnedHeightAtOrAbove(4031));
        Assertions.assertEquals(6047, checkpoints.getPinnedHeightAtOrAbove(4032));

        int maxHeight = checkpoints.getMaxHeight();
        Assertions.assertEquals(maxHeight, checkpoints.getPinnedHeightAtOrAbove(maxHeight));
        Assertions.assertEquals(maxHeight, checkpoints.getPinnedHeightAtOrAbove(maxHeight - HeaderChainState.RETARGET_INTERVAL + 1));
        Assertions.assertThrows(IllegalArgumentException.class, () -> checkpoints.getPinnedHeightAtOrAbove(maxHeight + 1));
        Assertions.assertThrows(IllegalArgumentException.class, () -> checkpoints.getPinnedHeightAtOrAbove(-1));
    }

    @Test
    public void testUnpinnedHeightRejected() {
        HeaderCheckpoints checkpoints = Network.MAINNET.getHeaderCheckpoints();
        Assertions.assertThrows(IllegalArgumentException.class, () -> checkpoints.getHash(2014));
        Assertions.assertThrows(IllegalArgumentException.class, () -> checkpoints.getHash(2016));
        Assertions.assertThrows(IllegalArgumentException.class, () -> checkpoints.getHash(checkpoints.getMaxHeight() + HeaderChainState.RETARGET_INTERVAL));
        Assertions.assertThrows(IllegalArgumentException.class, () -> checkpoints.getBitsAfter(2016));
    }

    @Test
    public void testRegtestAnchorsAtGenesis() {
        HeaderCheckpoints checkpoints = Network.REGTEST.getHeaderCheckpoints();
        Assertions.assertEquals(0, checkpoints.getMaxHeight());
        Assertions.assertEquals(Network.REGTEST.getGenesisHash(), checkpoints.getHash(0));
        Assertions.assertEquals(0x207fffffL, checkpoints.getBitsAfter(0));
        Assertions.assertEquals(0, checkpoints.getPinnedHeightAtOrAbove(0));
        Assertions.assertThrows(IllegalArgumentException.class, () -> checkpoints.getPinnedHeightAtOrAbove(1));
        Assertions.assertThrows(IllegalArgumentException.class, () -> checkpoints.getHash(2015));

        HeaderChainState chainState = checkpoints.newChainState();
        Assertions.assertEquals(0, chainState.getHeight());
        Assertions.assertEquals(Network.REGTEST.getGenesisHash(), chainState.getHash());
    }

    @Test
    public void testGenesisHeaders() {
        Assertions.assertEquals("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f", Network.MAINNET.getGenesisHash().toString());
        Assertions.assertEquals("000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943", Network.TESTNET.getGenesisHash().toString());
        Assertions.assertEquals("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206", Network.REGTEST.getGenesisHash().toString());
        Assertions.assertEquals("00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6", Network.SIGNET.getGenesisHash().toString());
        Assertions.assertEquals("00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043", Network.TESTNET4.getGenesisHash().toString());

        for(Network network : Network.values()) {
            Network.set(network);
            Assertions.assertTrue(network.getGenesisHeader().verifyProofOfWork(), network.getName());
            Assertions.assertEquals(Sha256Hash.ZERO_HASH, network.getGenesisHeader().getPrevBlockHash(), network.getName());
            Network.set(null);
        }
    }

    @Test
    public void testMalformedCheckpointsRejected() {
        Assertions.assertThrows(IllegalStateException.class, () -> parse(MAINNET_FIRST_PIN.substring(1) + " 1d00ffff"));
        Assertions.assertThrows(IllegalStateException.class, () -> parse(MAINNET_FIRST_PIN));
        Assertions.assertThrows(IllegalStateException.class, () -> parse(MAINNET_FIRST_PIN + " 1d00ffff extra"));
        Assertions.assertThrows(IllegalStateException.class, () -> parse(MAINNET_FIRST_PIN.replace('0', 'z') + " 1d00ffff"));
        Assertions.assertThrows(IllegalStateException.class, () -> parse(""));

        //A target that decodes as negative, as zero, or to a compact form other than the one written is not a consensus value
        Assertions.assertThrows(IllegalStateException.class, () -> parse(MAINNET_FIRST_PIN + " 1d80ffff"));
        Assertions.assertThrows(IllegalStateException.class, () -> parse(MAINNET_FIRST_PIN + " 00000000"));
        Assertions.assertThrows(IllegalStateException.class, () -> parse(MAINNET_FIRST_PIN + " 1d0000ff"));

        Assertions.assertDoesNotThrow(() -> parse(MAINNET_FIRST_PIN + " 1d00ffff"));
    }

    @Test
    public void testMalformedResourceForOneNetworkLeavesOthersLoadable() {
        Assertions.assertThrows(IllegalStateException.class, () -> parse("nonsense"));
        Assertions.assertNotNull(Network.MAINNET.getHeaderCheckpoints().getHash(2015));
    }

    private static HeaderCheckpoints parse(String content) throws IOException {
        return HeaderCheckpoints.parse(Network.MAINNET, new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8)));
    }

    @AfterEach
    public void tearDown() throws Exception {
        Network.set(null);
    }
}
