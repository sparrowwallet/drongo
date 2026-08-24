package com.sparrowwallet.drongo.protocol;

import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.Utils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class MerkleBranchTest {
    //Mainnet block 800000 (3721 transactions, tree depth 12), merkle root from BlockHeaderTest.BLOCK_800000_HEADER_HEX
    public static final String BLOCK_800000_MERKLE_ROOT = "91f01a00530c8c83617190048ea8b0814d506cf24dfdbcf8893f8f0cab7f0855";

    public static final String COINBASE_TXID = "b75ca3106ed100521aa50e3ec267a06431c6319538898b25e1b757a5736f5fb4";
    public static final List<String> COINBASE_BRANCH = List.of(
            "d41f5de48325e79070ccd3a23005f7a3b405f3ce1faa4df09f6d71770497e9d5",
            "e966899d07c2e59033c073820b2f37a11532c1d11184373c4e558d65dac475e0",
            "9f43ef264af1c3a4678d2bf5e60cddbd87b97618b1c80bd2b8a7f9b7f3baca68",
            "4befb427613b7021015030bf67472af6c76f680fadc90bc4c267a9e5804d8948",
            "bf61e05d4675710220c0b8dd669dcac9a1cbc3edb7ac64fc50410da9228333d5",
            "c88892d93e8110f2ec82c41ac30e6a3c8dfe8cf062fefb4b5c09ee754d7ce42c",
            "d4e7722bda133364a17b82990b16c3eb62f4a47d6aaae1c16bb0553806fcd3df",
            "2cbc00355a2debbb8b90dd60ab0dd520699b40e4e4ad90d546864a6e4c5087f8",
            "f2a33c753e9894eea7728206d927e830e946c4e13706275df14362398538e3db",
            "8cc2c566df38c865e0aa6ddfd46d3440e99442a6d04d567323cbe53ffa470234",
            "885cd4d205c35e05f8f738328166b9c65304583704162bcac8944b20690f696f",
            "f6d90508da8aa581f7203f4899498c775ed4878544adcdef5e7b53a4ab691dd7");

    public static final String MIDDLE_TXID = "48a394fc30814d3ee3b6b119d712e9d6adc96f1eb02066e15439b2871dc7226c";
    public static final List<String> MIDDLE_BRANCH = List.of(
            "6c42dd79480debd1795d8d49d7c9f2dfac8614425a8855896b556ec61691cd6c",
            "aed25f02a346c2213964189cd02723c7434235253cfa2c6d6a8fde6d8817bbe4",
            "207d52964a861ea88fff162663e1e1b4c801fe17f6cb2e6bb0ce5d6c9a950de6",
            "c0cac4b52f2cf7e0780dd414d4664e59a5bfd70e122cf54ec02abe613b011ca2",
            "8b99dd0c042bd615d79d1c1b3eea0e4ea10e175d7554893ec315c3914cb49c2e",
            "c44b69638caeb34ab7ea38b9a8676b6fd8143794621c55f7454706feb8512e7e",
            "29bbe3c749e4b40119371d7625aa066a5876d818857e6387bca44424dd34c47f",
            "8aa82acb511a720d9fa320ecbda2c22dc97484fc410ab599247136cf49c4a42e",
            "8a3ec68a787bc970061776e6b0e1a61b375cec565eb9fa628f03a1ee4b5d9976",
            "bb79dc5d8bd230d39040c7e04db757a95a08f5f23784b255c33341471a8de9fc",
            "885cd4d205c35e05f8f738328166b9c65304583704162bcac8944b20690f696f",
            "f6d90508da8aa581f7203f4899498c775ed4878544adcdef5e7b53a4ab691dd7");

    public static final String LAST_TXID = "b2088e443cf4b28ade8873cc6b3f6a67557f104ec4dc5b5e293c12973ab8b6b8";
    public static final List<String> LAST_BRANCH = List.of(
            "b2088e443cf4b28ade8873cc6b3f6a67557f104ec4dc5b5e293c12973ab8b6b8",
            "778bbd523169d42a569216ea7a8a7b1523e34d966d3e9bf01cf00885ee01701a",
            "7ccd03b9676c65257877c249a02148d6e16b225f49239799164c81bf3e3266e1",
            "6b35ab4bf94b863c843ad4f84b1ad372cba286f1126e0060730484ead0a7246b",
            "c3976dd2786ccf026f15e9867f443e6f84b5eefb7ec1dea13aea4ed077f716c1",
            "ace932d5362a191223682e948120fa4000df2625722bf8a006ad45f74ad33e1d",
            "2b58afe20f14150bd6e09ba54388488e656b060219c81a9bd1aeb178d158ac2b",
            "4c5600a65b4be41d2e81ebf32f30d0e98e9849c6a8fcc75b774fc5e3d1ca9e5d",
            "65b0b0553d106bf379f91d07616e0423c1f1fa20794aeb1239e9b184d462e68c",
            "e251b33fc73d02c3c8764758f9bcfa5e3ee5f6e9fde3fcf90b3666c32352fdb3",
            "bdce3727f74cc85d3ec624978f99e7994ff1dd6d419308cf43242c6f36784074",
            "0ece9245ca886685f8210cba8996777e87daa70da5cc40d30f489db1f75309f2");

    //CVE-2017-12842 vectors, from Electrum tests/test_verifier.py: an actually mined 64 byte testnet transaction and its branch
    public static final String VALID_64_BYTE_TX = "0200000001cb659c5528311901a7aada7db817bd6e3ce2f05d1c62c385b7caadb65fac75201234000000fabcdefa01abcd1234010000000405060708fabcdefa";
    public static final List<String> CVE_2017_12842_BRANCH = List.of(
            "f2994fd4546086b21b4916b76cf901afb5c4db1c3ecbfc91d6f4cae1186dfe12",
            "6b65935528311901c7acda7db817bd6e3ce2f05d1c62c385b7caadb65fac7520");
    public static final String CVE_2017_12842_MERKLE_ROOT = "11dbac015b6969ea75509dd1250f33c04ec4d562c2d895de139a65f62f808254";

    //CVE-2012-2459 vectors, from Electrum tests/test_verifier.py: testnet3 block 4909055, three transactions, so the last leaf is duplicated
    public static final List<String> CVE_2012_2459_BRANCH = List.of(
            "9b2c7e407188465594832cfbe84c9758029084527c855ea29a16603e5d1c51b6",
            "a8484ccbaa74ffa060d0a500f7ce3ea4953beace18df8384024dfa9290385b1c");
    public static final String CVE_2012_2459_MERKLE_ROOT = "3465af659f6438b133c6d980accbb61b7be43f8ad899e40054e33b37aecba28e";
    public static final String CVE_2012_2459_TXID = "9b2c7e407188465594832cfbe84c9758029084527c855ea29a16603e5d1c51b6";

    @Test
    public void testBlock800000CoinbaseProof() {
        Network.set(Network.MAINNET);

        MerkleBranch branch = branch(0, COINBASE_BRANCH);
        Assertions.assertEquals(12, branch.getDepth());
        Assertions.assertEquals(Sha256Hash.wrap(BLOCK_800000_MERKLE_ROOT), branch.computeRoot(Sha256Hash.wrap(COINBASE_TXID)));
    }

    @Test
    public void testBlock800000Proof() {
        Network.set(Network.MAINNET);

        MerkleBranch branch = branch(1000, MIDDLE_BRANCH);
        Assertions.assertEquals(Sha256Hash.wrap(BLOCK_800000_MERKLE_ROOT), branch.computeRoot(Sha256Hash.wrap(MIDDLE_TXID)));
    }

    @Test
    public void testBlock800000LastTransactionProof() {
        Network.set(Network.MAINNET);

        //The block has an odd number of transactions, so the last leaf is its own right sibling at level 0
        MerkleBranch branch = branch(3720, LAST_BRANCH);
        Assertions.assertEquals(Sha256Hash.wrap(BLOCK_800000_MERKLE_ROOT), branch.computeRoot(Sha256Hash.wrap(LAST_TXID)));
    }

    @Test
    public void testBlock800000ProofFailsAgainstWrongLeaf() {
        Network.set(Network.MAINNET);

        MerkleBranch branch = branch(1000, MIDDLE_BRANCH);
        Assertions.assertNotEquals(Sha256Hash.wrap(BLOCK_800000_MERKLE_ROOT), branch.computeRoot(Sha256Hash.wrap(COINBASE_TXID)));
    }

    @Test
    public void testBlock800000ProofFailsAtWrongPosition() {
        Network.set(Network.MAINNET);

        MerkleBranch branch = branch(1001, MIDDLE_BRANCH);
        Assertions.assertNotEquals(Sha256Hash.wrap(BLOCK_800000_MERKLE_ROOT), branch.computeRoot(Sha256Hash.wrap(MIDDLE_TXID)));
    }

    @Test
    public void testMinedSixtyFourByteTransactionVerifies() {
        Network.set(Network.TESTNET);

        Transaction transaction = new Transaction(Utils.hexToBytes(VALID_64_BYTE_TX));
        MerkleBranch branch = branch(3, CVE_2017_12842_BRANCH);
        Assertions.assertEquals(Sha256Hash.wrap(CVE_2017_12842_MERKLE_ROOT), branch.computeRoot(transaction.getTxId()));
    }

    @Test
    public void testInnerNodeIsValidTransactionAtOddPosition() {
        Network.set(Network.TESTNET);

        //The fake leaf is the last 32 bytes of the mined transaction, with its first 32 bytes prepended to the branch as the left sibling
        byte[] rawTransaction = Utils.hexToBytes(VALID_64_BYTE_TX);
        Sha256Hash fakeLeaf = Sha256Hash.wrapReversed(Arrays.copyOfRange(rawTransaction, 32, 64));
        Sha256Hash fakeNode = Sha256Hash.wrapReversed(Arrays.copyOfRange(rawTransaction, 0, 32));
        MerkleBranch branch = new MerkleBranch(7, prepend(fakeNode, CVE_2017_12842_BRANCH));
        VerificationException e = Assertions.assertThrows(VerificationException.class, () -> branch.computeRoot(fakeLeaf));
        Assertions.assertEquals("Merkle branch inner node at level 0 is a valid transaction", e.getMessage());
    }

    @Test
    public void testInnerNodeIsValidTransactionAtEvenPosition() {
        Network.set(Network.TESTNET);

        //The same forgery with the halves exchanged, so the fake leaf is the left child
        byte[] rawTransaction = Utils.hexToBytes(VALID_64_BYTE_TX);
        Sha256Hash fakeLeaf = Sha256Hash.wrapReversed(Arrays.copyOfRange(rawTransaction, 0, 32));
        Sha256Hash fakeNode = Sha256Hash.wrapReversed(Arrays.copyOfRange(rawTransaction, 32, 64));
        MerkleBranch branch = new MerkleBranch(6, prepend(fakeNode, CVE_2017_12842_BRANCH));
        VerificationException e = Assertions.assertThrows(VerificationException.class, () -> branch.computeRoot(fakeLeaf));
        Assertions.assertEquals("Merkle branch inner node at level 0 is a valid transaction", e.getMessage());
    }

    @Test
    public void testRightSiblingDuplicateVerifies() {
        Network.set(Network.TESTNET);

        //The third of three transactions is duplicated to balance the tree, which is legitimate at its real position
        MerkleBranch branch = branch(2, CVE_2012_2459_BRANCH);
        Assertions.assertEquals(Sha256Hash.wrap(CVE_2012_2459_MERKLE_ROOT), branch.computeRoot(Sha256Hash.wrap(CVE_2012_2459_TXID)));
    }

    @Test
    public void testLeftSiblingDuplicateRejected() {
        Network.set(Network.TESTNET);

        //The same branch at the phantom position presents the duplicate as a left sibling, which a genuine branch never does
        MerkleBranch branch = branch(3, CVE_2012_2459_BRANCH);
        VerificationException e = Assertions.assertThrows(VerificationException.class, () -> branch.computeRoot(Sha256Hash.wrap(CVE_2012_2459_TXID)));
        Assertions.assertEquals("Merkle branch has a duplicated left sibling at level 0", e.getMessage());
    }

    @Test
    public void testNegativePositionRejected() {
        Assertions.assertThrows(ProtocolException.class, () -> branch(-1, CVE_2017_12842_BRANCH));
    }

    @Test
    public void testPositionBeyondBranchDepthRejected() {
        Assertions.assertThrows(ProtocolException.class, () -> branch(4, CVE_2017_12842_BRANCH));
    }

    @Test
    public void testEmptyBranchVerifiesOnlyAtPositionZero() {
        Network.set(Network.MAINNET);

        //A single transaction block: the txid is the merkle root
        MerkleBranch branch = new MerkleBranch(0, List.of());
        Assertions.assertEquals(Sha256Hash.wrap(COINBASE_TXID), branch.computeRoot(Sha256Hash.wrap(COINBASE_TXID)));
        Assertions.assertThrows(ProtocolException.class, () -> new MerkleBranch(1, List.of()));
    }

    @Test
    public void testMutatingTheSuppliedListCannotAlterTheBranch() {
        Network.set(Network.MAINNET);

        //Truncating the caller's list must not shorten the branch, which would otherwise reduce the root to the leaf itself
        List<Sha256Hash> hashes = new ArrayList<>(MIDDLE_BRANCH.stream().map(Sha256Hash::wrap).toList());
        MerkleBranch branch = new MerkleBranch(1000, hashes);
        hashes.clear();
        Assertions.assertEquals(12, branch.getDepth());
        Assertions.assertEquals(Sha256Hash.wrap(BLOCK_800000_MERKLE_ROOT), branch.computeRoot(Sha256Hash.wrap(MIDDLE_TXID)));
    }

    @Test
    public void testBranchDeeperThanMaximumRejected() {
        List<Sha256Hash> hashes = new ArrayList<>();
        for(int i = 0; i < MerkleBranch.MAX_DEPTH + 1; i++) {
            hashes.add(Sha256Hash.wrap(COINBASE_TXID));
        }

        Assertions.assertThrows(ProtocolException.class, () -> new MerkleBranch(0, hashes));
    }

    private static MerkleBranch branch(int position, List<String> hashes) {
        return new MerkleBranch(position, hashes.stream().map(Sha256Hash::wrap).toList());
    }

    private static List<Sha256Hash> prepend(Sha256Hash hash, List<String> hashes) {
        List<Sha256Hash> branch = new ArrayList<>();
        branch.add(hash);
        hashes.stream().map(Sha256Hash::wrap).forEach(branch::add);
        return branch;
    }

    @AfterEach
    public void tearDown() throws Exception {
        Network.set(null);
    }
}
