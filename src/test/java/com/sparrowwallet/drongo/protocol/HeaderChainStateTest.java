package com.sparrowwallet.drongo.protocol;

import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.Utils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class HeaderChainStateTest {
    //Mainnet block 808415, the last header of difficulty period 400, and the target period 401 is required to use
    private static final int MAINNET_ANCHOR_HEIGHT = 808415;
    private static final String MAINNET_ANCHOR_HASH = "000000000000000000027ecc78c2da1cc5c0b0496706baa7e4d7c80812c10bf3";
    private static final long MAINNET_ANCHOR_BITS = 0x1704ed7fL;

    //Testnet3 block 3630815, the last header of difficulty period 1800. Its period contains minimum difficulty headers, the first at offset 5
    private static final int TESTNET_ANCHOR_HEIGHT = 3630815;
    private static final String TESTNET_ANCHOR_HASH = "00000000000010047f90a66416b399f265a55d9dbeed30cd320ae2c1cfe4ace3";
    private static final long TESTNET_ANCHOR_BITS = 0x1b0ffff0L;
    private static final int TESTNET_FIRST_MIN_DIFFICULTY_OFFSET = 5;

    //Mainnet difficulty period 15 in full (heights 30240 to 32255) plus the header at 32256, the chain's first ever difficulty rise
    private static final int MAINNET_PERIOD_ANCHOR_HEIGHT = 30239;
    private static final int MAINNET_PERIOD_HEADERS = 2017;
    private static final long MAINNET_FIRST_RISE_BITS = 0x1d00d86aL;

    @Test
    public void testEveryMainnetRetarget() throws IOException {
        Network.set(Network.MAINNET);

        //Every difficulty adjustment in mainnet's history: the closing period's bits and timestamps against the target the chain actually adopted
        int retargets = 0;
        for(String line : readLines("/headers/mainnet-retargets.txt")) {
            String[] parts = line.split(" ");
            int height = Integer.parseInt(parts[0]);
            long lastBits = Long.parseLong(parts[1], 16);
            long firstTime = Long.parseLong(parts[2]);
            long lastTime = Long.parseLong(parts[3]);
            long expectedBits = Long.parseLong(parts[4], 16);
            Assertions.assertEquals(expectedBits, HeaderChainState.calculateNextWorkRequired(lastBits, firstTime, lastTime), "Retarget at height " + height);
            retargets++;
        }

        Assertions.assertEquals(478, retargets);
    }

    @Test
    public void testRetargetClampedAtFourTimes() {
        Network.set(Network.MAINNET);

        //A period taking a year still only quadruples the target
        long slow = HeaderChainState.calculateNextWorkRequired(0x1704ed7fL, 0, 365 * 24 * 60 * 60);
        long clamped = HeaderChainState.calculateNextWorkRequired(0x1704ed7fL, 0, HeaderChainState.TARGET_TIMESPAN_SECS * 4L);
        Assertions.assertEquals(clamped, slow);
        Assertions.assertEquals(Utils.decodeCompactBits(0x1704ed7fL).multiply(BigInteger.valueOf(4)), Utils.decodeCompactBits(slow));
    }

    @Test
    public void testRetargetClampedAtQuarter() {
        Network.set(Network.MAINNET);

        //A period mined in an hour still only quarters the target
        long fast = HeaderChainState.calculateNextWorkRequired(0x1704ed7fL, 0, 60 * 60);
        long clamped = HeaderChainState.calculateNextWorkRequired(0x1704ed7fL, 0, HeaderChainState.TARGET_TIMESPAN_SECS / 4);
        Assertions.assertEquals(clamped, fast);
        //A quarter of this target does not fit the compact mantissa, so the consensus value is the truncation of it
        Assertions.assertEquals(Utils.encodeCompactBits(Utils.decodeCompactBits(0x1704ed7fL).divide(BigInteger.valueOf(4))), fast);
    }

    @Test
    public void testRetargetClampedAtProofOfWorkLimit() {
        Network.set(Network.MAINNET);

        //An already minimum difficulty period that took four times too long cannot get any easier
        Assertions.assertEquals(0x1d00ffffL, HeaderChainState.calculateNextWorkRequired(0x1d00ffffL, 0, HeaderChainState.TARGET_TIMESPAN_SECS * 4L));
        Assertions.assertEquals(Network.MAINNET.getProofOfWorkLimit(), Utils.decodeCompactBits(0x1d00ffffL));
    }

    @Test
    public void testMainnetHeadersAboveAnchorAccepted() throws IOException {
        Network.set(Network.MAINNET);

        List<BlockHeader> headers = readHeaders("/headers/mainnet-window.txt");
        HeaderChainState chainState = new HeaderChainState(MAINNET_ANCHOR_HEIGHT, Sha256Hash.wrap(MAINNET_ANCHOR_HASH), MAINNET_ANCHOR_BITS);
        for(BlockHeader header : headers) {
            chainState.add(header);
        }

        Assertions.assertEquals(MAINNET_ANCHOR_HEIGHT + headers.size(), chainState.getHeight());
        Assertions.assertEquals(headers.get(headers.size() - 1).getHash(), chainState.getHash());
        Assertions.assertEquals(HeaderChainState.getWork(MAINNET_ANCHOR_BITS).multiply(BigInteger.valueOf(headers.size())), chainState.getChainWork());
    }

    @Test
    public void testRetargetAcrossARealPeriodBoundary() throws IOException {
        Network.set(Network.MAINNET);

        //A full difficulty period walked header by header, ending at the chain's first difficulty rise: the required target for the closing
        //header is computed, not adopted, so accepting the real chain here is the guard on the 2015 interval timespan
        HeaderCheckpoints checkpoints = Network.MAINNET.getHeaderCheckpoints();
        List<BlockHeader> headers = readBinaryHeaders("/headers/mainnet-period.bin");
        Assertions.assertEquals(MAINNET_PERIOD_HEADERS, headers.size());

        HeaderChainState chainState = new HeaderChainState(MAINNET_PERIOD_ANCHOR_HEIGHT, checkpoints.getHash(MAINNET_PERIOD_ANCHOR_HEIGHT),
                checkpoints.getBitsAfter(MAINNET_PERIOD_ANCHOR_HEIGHT));
        for(BlockHeader header : headers) {
            chainState.add(header);
        }

        BlockHeader boundary = headers.get(headers.size() - 1);
        Assertions.assertEquals(MAINNET_PERIOD_ANCHOR_HEIGHT + MAINNET_PERIOD_HEADERS, chainState.getHeight());
        Assertions.assertEquals(HeaderChainState.RETARGET_INTERVAL * 16, chainState.getHeight());
        Assertions.assertEquals(MAINNET_FIRST_RISE_BITS, boundary.getDifficultyTarget());
        Assertions.assertEquals(HeaderChainState.getWork(0x1d00ffffL).multiply(BigInteger.valueOf(MAINNET_PERIOD_HEADERS - 1))
                .add(HeaderChainState.getWork(MAINNET_FIRST_RISE_BITS)), chainState.getChainWork());
    }

    @Test
    public void testBoundaryHeaderKeepingTheOldTargetRejected() throws IOException {
        Network.set(Network.MAINNET);

        //The same walk, with the closing header claiming the period's target rather than the retargeted one
        HeaderCheckpoints checkpoints = Network.MAINNET.getHeaderCheckpoints();
        List<BlockHeader> headers = readBinaryHeaders("/headers/mainnet-period.bin");
        HeaderChainState chainState = new HeaderChainState(MAINNET_PERIOD_ANCHOR_HEIGHT, checkpoints.getHash(MAINNET_PERIOD_ANCHOR_HEIGHT),
                checkpoints.getBitsAfter(MAINNET_PERIOD_ANCHOR_HEIGHT));
        for(int i = 0; i < headers.size() - 1; i++) {
            chainState.add(headers.get(i));
        }

        BlockHeader boundary = headers.get(headers.size() - 1);
        BlockHeader unadjusted = new BlockHeader(boundary.getVersion(), boundary.getPrevBlockHash(), boundary.getMerkleRoot(), null, boundary.getTime(), 0x1d00ffffL, boundary.getNonce());
        VerificationException e = Assertions.assertThrows(VerificationException.class, () -> chainState.add(unadjusted));
        Assertions.assertEquals("Header at height " + (HeaderChainState.RETARGET_INTERVAL * 16) + " has difficulty target 1d00ffff but the chain requires 1d00d86a", e.getMessage());
    }

    @Test
    public void testRetargetWithoutAnObservedPeriodStartRefused() {
        Network.set(Network.REGTEST);

        //A height 0 anchor sits at the first header of a period rather than the last, so no period start is ever recorded and the retarget has
        //nothing to measure from. Only regtest anchors that way and only regtest can mine 2016 headers here, so the last header is added under
        //the full rules to reach the branch a height 0 anchor on mainnet or signet would otherwise reach silently
        HeaderChainState chainState = Network.REGTEST.getHeaderCheckpoints().newChainState();
        BlockHeader previous = Network.REGTEST.getGenesisHeader();
        for(int i = 0; i < HeaderChainState.RETARGET_INTERVAL - 1; i++) {
            previous = mineRegtestHeader(previous, 1600000000L + i);
            chainState.add(previous);
        }

        Assertions.assertEquals(HeaderChainState.RETARGET_INTERVAL - 1, chainState.getHeight());
        BlockHeader boundary = mineRegtestHeader(previous, 1600000000L + HeaderChainState.RETARGET_INTERVAL);
        Network.set(Network.MAINNET);
        VerificationException e = Assertions.assertThrows(VerificationException.class, () -> chainState.add(boundary));
        Assertions.assertEquals("Cannot retarget at height " + HeaderChainState.RETARGET_INTERVAL + ": no difficulty period has started since the anchor at height 0", e.getMessage());
    }

    @Test
    public void testFirstHeaderAfterAnchorMustClaimThePinnedTarget() throws IOException {
        Network.set(Network.MAINNET);

        //An anchor pinning the wrong target rejects the real chain's first header, proving the pinned bits are enforced rather than adopted
        BlockHeader first = readHeaders("/headers/mainnet-window.txt").get(0);
        HeaderChainState chainState = new HeaderChainState(MAINNET_ANCHOR_HEIGHT, Sha256Hash.wrap(MAINNET_ANCHOR_HASH), 0x1d00ffffL);
        VerificationException e = Assertions.assertThrows(VerificationException.class, () -> chainState.add(first));
        Assertions.assertTrue(e.getMessage().contains("requires 1d00ffff"), e.getMessage());
    }

    @Test
    public void testMinimumDifficultyRunRejectedUnderFullRules() throws IOException {
        Network.set(Network.MAINNET);

        //The attack per-header proof of work cannot stop: a linked run of real, well-formed headers that simply claim an easier target than the chain requires
        List<BlockHeader> headers = readHeaders("/headers/testnet-window.txt");
        HeaderChainState chainState = new HeaderChainState(TESTNET_ANCHOR_HEIGHT, Sha256Hash.wrap(TESTNET_ANCHOR_HASH), TESTNET_ANCHOR_BITS);
        for(int i = 0; i < TESTNET_FIRST_MIN_DIFFICULTY_OFFSET; i++) {
            chainState.add(headers.get(i));
        }

        BlockHeader minimumDifficulty = headers.get(TESTNET_FIRST_MIN_DIFFICULTY_OFFSET);
        Assertions.assertEquals(0x1d00ffffL, minimumDifficulty.getDifficultyTarget());
        Assertions.assertTrue(minimumDifficulty.verifyProofOfWork());
        VerificationException e = Assertions.assertThrows(VerificationException.class, () -> chainState.add(minimumDifficulty));
        Assertions.assertEquals("Header at height " + (TESTNET_ANCHOR_HEIGHT + TESTNET_FIRST_MIN_DIFFICULTY_OFFSET + 1) + " has difficulty target 1d00ffff but the chain requires 1b0ffff0",
                e.getMessage());
    }

    @Test
    public void testMinimumDifficultyRunAcceptedOnTestnet() throws IOException {
        Network.set(Network.TESTNET);

        //The same headers are the real testnet chain, so the relaxed rules accept them and count each as one unit of work
        List<BlockHeader> headers = readHeaders("/headers/testnet-window.txt");
        HeaderChainState chainState = new HeaderChainState(TESTNET_ANCHOR_HEIGHT, Sha256Hash.wrap(TESTNET_ANCHOR_HASH), TESTNET_ANCHOR_BITS);
        for(BlockHeader header : headers) {
            chainState.add(header);
        }

        Assertions.assertEquals(TESTNET_ANCHOR_HEIGHT + headers.size(), chainState.getHeight());
        Assertions.assertEquals(BigInteger.valueOf(headers.size()), chainState.getChainWork());
    }

    @Test
    public void testUnlinkedHeaderRejected() throws IOException {
        Network.set(Network.MAINNET);

        List<BlockHeader> headers = readHeaders("/headers/mainnet-window.txt");
        HeaderChainState chainState = new HeaderChainState(MAINNET_ANCHOR_HEIGHT, Sha256Hash.wrap(MAINNET_ANCHOR_HASH), MAINNET_ANCHOR_BITS);
        chainState.add(headers.get(0));
        VerificationException e = Assertions.assertThrows(VerificationException.class, () -> chainState.add(headers.get(2)));
        Assertions.assertEquals("Header at height " + (MAINNET_ANCHOR_HEIGHT + 2) + " does not link to the previous header", e.getMessage());
    }

    @Test
    public void testHeaderFailingProofOfWorkRejected() throws IOException {
        Network.set(Network.MAINNET);

        //Tampering with the nonce leaves the claimed target intact but breaks the hash
        byte[] tampered = readHeaders("/headers/mainnet-window.txt").get(0).bitcoinSerialize();
        tampered[79] ^= 0x01;
        BlockHeader header = new BlockHeader(tampered);
        HeaderChainState chainState = new HeaderChainState(MAINNET_ANCHOR_HEIGHT, Sha256Hash.wrap(MAINNET_ANCHOR_HASH), MAINNET_ANCHOR_BITS);
        VerificationException e = Assertions.assertThrows(VerificationException.class, () -> chainState.add(header));
        Assertions.assertTrue(e.getMessage().contains("proof of work"), e.getMessage());
    }

    @Test
    public void testMedianTimePastViolationRejected() {
        Network.set(Network.REGTEST);

        //Regtest's trivial target makes a synthetic chain mineable, which is the only way to build a chain that violates a consensus rule
        HeaderChainState chainState = Network.REGTEST.getHeaderCheckpoints().newChainState();
        Assertions.assertEquals(0, chainState.getHeight());
        Assertions.assertEquals(Network.REGTEST.getGenesisHash(), chainState.getHash());

        BlockHeader previous = Network.REGTEST.getGenesisHeader();
        List<Long> times = new ArrayList<>();
        for(int i = 0; i < 11; i++) {
            previous = mineRegtestHeader(previous, 1600000000L + i);
            times.add(1600000000L + i);
            chainState.add(previous);
        }

        //The median of the last eleven timestamps, which the twelfth header must exceed
        BlockHeader atMedian = mineRegtestHeader(previous, times.get(5));
        VerificationException e = Assertions.assertThrows(VerificationException.class, () -> chainState.add(atMedian));
        Assertions.assertTrue(e.getMessage().contains("median"), e.getMessage());

        BlockHeader aboveMedian = mineRegtestHeader(previous, times.get(5) + 1);
        chainState.add(aboveMedian);
        Assertions.assertEquals(12, chainState.getHeight());
        Assertions.assertEquals(BigInteger.valueOf(12), chainState.getChainWork());
    }

    @Test
    public void testWork() {
        Network.set(Network.MAINNET);

        //The chain work a difficulty one block contributes, as Bitcoin Core reports it as the genesis block's chainwork
        Assertions.assertEquals(BigInteger.valueOf(4295032833L), HeaderChainState.getWork(0x1d00ffffL));
        Assertions.assertEquals(new BigInteger("245331722670144073701996"), HeaderChainState.getWork(MAINNET_ANCHOR_BITS));
        //A harder target is more work, and the genesis block's chain work is that of a single difficulty one block
        Assertions.assertTrue(HeaderChainState.getWork(MAINNET_ANCHOR_BITS).compareTo(HeaderChainState.getWork(0x1d00ffffL)) > 0);
    }

    @Test
    public void testAnchorMustBeAPeriodBoundary() {
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> new HeaderChainState(MAINNET_ANCHOR_HEIGHT - 1, Sha256Hash.wrap(MAINNET_ANCHOR_HASH), MAINNET_ANCHOR_BITS));
        Assertions.assertDoesNotThrow(() -> new HeaderChainState(0, Sha256Hash.wrap(MAINNET_ANCHOR_HASH), MAINNET_ANCHOR_BITS));
        Assertions.assertDoesNotThrow(() -> new HeaderChainState(HeaderChainState.RETARGET_INTERVAL - 1, Sha256Hash.wrap(MAINNET_ANCHOR_HASH), MAINNET_ANCHOR_BITS));
    }

    private static BlockHeader mineRegtestHeader(BlockHeader previous, long time) {
        for(long nonce = 0; nonce < 1000; nonce++) {
            BlockHeader header = new BlockHeader(1, previous.getHash(), Sha256Hash.ZERO_HASH, null, time, 0x207fffffL, nonce);
            if(header.verifyProofOfWork()) {
                return header;
            }
        }

        throw new IllegalStateException("Could not mine a regtest header at time " + time);
    }

    private static List<BlockHeader> readBinaryHeaders(String resource) throws IOException {
        try(InputStream inputStream = HeaderChainStateTest.class.getResourceAsStream(resource)) {
            Assertions.assertNotNull(inputStream, "Missing test resource " + resource);
            byte[] data = inputStream.readAllBytes();
            Assertions.assertEquals(0, data.length % 80, "Header data is not a whole number of headers");
            List<BlockHeader> headers = new ArrayList<>();
            for(int offset = 0; offset < data.length; offset += 80) {
                headers.add(new BlockHeader(data, offset));
            }

            return headers;
        }
    }

    private static List<BlockHeader> readHeaders(String resource) throws IOException {
        List<BlockHeader> headers = new ArrayList<>();
        for(String line : readLines(resource)) {
            headers.add(new BlockHeader(Utils.hexToBytes(line)));
        }

        return headers;
    }

    private static List<String> readLines(String resource) throws IOException {
        try(InputStream inputStream = HeaderChainStateTest.class.getResourceAsStream(resource)) {
            Assertions.assertNotNull(inputStream, "Missing test resource " + resource);
            BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8));
            List<String> lines = new ArrayList<>();
            String line;
            while((line = reader.readLine()) != null) {
                if(!line.isBlank()) {
                    lines.add(line.trim());
                }
            }

            return lines;
        }
    }

    @AfterEach
    public void tearDown() throws Exception {
        Network.set(null);
    }
}
