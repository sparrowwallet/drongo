package com.sparrowwallet.drongo.protocol;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.address.Address;
import com.sparrowwallet.drongo.address.InvalidAddressException;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.crypto.SchnorrSignature;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

public class TransactionTest {
    @Test
    public void verifyP2WPKH() {
        String hex = "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000";
        Transaction transaction = new Transaction(Utils.hexToBytes(hex));

        ECKey pubKey = ECKey.fromPublicOnly(Utils.hexToBytes("025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357"));
        Sha256Hash hash = transaction.hashForWitnessSignature(1, ScriptType.P2PKH.getOutputScript(pubKey.getPubKeyHash()),600000000L, SigHash.ALL);
        TransactionSignature signature = TransactionSignature.decodeFromBitcoin(Utils.hexToBytes("304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee"), false);
        Assertions.assertTrue(pubKey.verify(hash, signature));
    }

    @Test
    public void verifyP2SHP2WPKH() {
        String hex = "0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000";
        Transaction transaction = new Transaction(Utils.hexToBytes(hex));

        ECKey pubKey = ECKey.fromPublicOnly(Utils.hexToBytes("03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873"));
        Sha256Hash hash = transaction.hashForWitnessSignature(0, ScriptType.P2PKH.getOutputScript(pubKey.getPubKeyHash()),1000000000L, SigHash.ALL);
        TransactionSignature signature = TransactionSignature.decodeFromBitcoin(Utils.hexToBytes("3044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb01"), true);
        Assertions.assertTrue(pubKey.verify(hash, signature));
    }

    @Test
    public void verifyP2WSHSigHashSingle() {
        String hex = "0100000002fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c565d1c6b9216b36e0000000000ffffffff0815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f80000000000ffffffff0100f2052a010000001976a914a30741f8145e5acadf23f751864167f32e0963f788ac00000000";
        Transaction transaction = new Transaction(Utils.hexToBytes(hex));

        ECKey pubKey = ECKey.fromPublicOnly(Utils.hexToBytes("026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880ae"));
        Script script = new Script(Utils.hexToBytes("21026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac"));
        Sha256Hash hash = transaction.hashForWitnessSignature(1, script,4900000000L, SigHash.SINGLE);
        TransactionSignature signature = TransactionSignature.decodeFromBitcoin(Utils.hexToBytes("3044022027dc95ad6b740fe5129e7e62a75dd00f291a2aeb1200b84b09d9e3789406b6c002201a9ecd315dd6a0e632ab20bbb98948bc0c6fb204f2c286963bb48517a7058e2703"), true);
        Assertions.assertTrue(pubKey.verify(hash, signature));
    }

    @Test
    public void verifyP2WSHSigHashSingleAnyoneCanPay() {
        String hex = "0100000002e9b542c5176808107ff1df906f46bb1f2583b16112b95ee5380665ba7fcfc0010000000000ffffffff80e68831516392fcd100d186b3c2c7b95c80b53c77e77c35ba03a66b429a2a1b0000000000ffffffff0280969800000000001976a914de4b231626ef508c9a74a8517e6783c0546d6b2888ac80969800000000001976a9146648a8cd4531e1ec47f35916de8e259237294d1e88ac00000000";
        Transaction transaction = new Transaction(Utils.hexToBytes(hex));

        ECKey pubKey = ECKey.fromPublicOnly(Utils.hexToBytes("0392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98"));
        Script script = new Script(Utils.hexToBytes("68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac"));
        Sha256Hash hash = transaction.hashForWitnessSignature(1, script,16777215L, SigHash.ANYONECANPAY_SINGLE);
        TransactionSignature signature = TransactionSignature.decodeFromBitcoin(Utils.hexToBytes("30440220032521802a76ad7bf74d0e2c218b72cf0cbc867066e2e53db905ba37f130397e02207709e2188ed7f08f4c952d9d13986da504502b8c3be59617e043552f506c46ff83"), true);
        Assertions.assertTrue(pubKey.verify(hash, signature));
    }

    @Test
    public void verifyP2SHP2WSHSigHashAll() {
        String hex = "010000000136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000000ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac00000000";
        Transaction transaction = new Transaction(Utils.hexToBytes(hex));

        ECKey pubKey = ECKey.fromPublicOnly(Utils.hexToBytes("0307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba3"));
        Script script = new Script(Utils.hexToBytes("56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae"));
        Sha256Hash hash = transaction.hashForWitnessSignature(0, script,987654321L, SigHash.ALL);
        TransactionSignature signature = TransactionSignature.decodeFromBitcoin(Utils.hexToBytes("304402206ac44d672dac41f9b00e28f4df20c52eeb087207e8d758d76d92c6fab3b73e2b0220367750dbbe19290069cba53d096f44530e4f98acaa594810388cf7409a1870ce01"), true);
        Assertions.assertTrue(pubKey.verify(hash, signature));
    }

    @Test
    public void verifyP2SHP2WSHSigHashNone() {
        String hex = "010000000136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000000ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac00000000";
        Transaction transaction = new Transaction(Utils.hexToBytes(hex));

        ECKey pubKey = ECKey.fromPublicOnly(Utils.hexToBytes("03b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b"));
        Script script = new Script(Utils.hexToBytes("56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae"));
        Sha256Hash hash = transaction.hashForWitnessSignature(0, script,987654321L, SigHash.NONE);
        TransactionSignature signature = TransactionSignature.decodeFromBitcoin(Utils.hexToBytes("3044022068c7946a43232757cbdf9176f009a928e1cd9a1a8c212f15c1e11ac9f2925d9002205b75f937ff2f9f3c1246e547e54f62e027f64eefa2695578cc6432cdabce271502"), true);
        Assertions.assertTrue(pubKey.verify(hash, signature));
    }

    @Test
    public void verifyP2SHP2WSHSigHashSingle() {
        String hex = "010000000136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000000ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac00000000";
        Transaction transaction = new Transaction(Utils.hexToBytes(hex));

        ECKey pubKey = ECKey.fromPublicOnly(Utils.hexToBytes("034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a"));
        Script script = new Script(Utils.hexToBytes("56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae"));
        Sha256Hash hash = transaction.hashForWitnessSignature(0, script,987654321L, SigHash.SINGLE);
        TransactionSignature signature = TransactionSignature.decodeFromBitcoin(Utils.hexToBytes("3044022059ebf56d98010a932cf8ecfec54c48e6139ed6adb0728c09cbe1e4fa0915302e022007cd986c8fa870ff5d2b3a89139c9fe7e499259875357e20fcbb15571c76795403"), true);
        Assertions.assertTrue(pubKey.verify(hash, signature));
    }

    @Test
    public void verifyP2SHP2WSHSigHashAllAnyoneCanPay() {
        String hex = "010000000136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000000ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac00000000";
        Transaction transaction = new Transaction(Utils.hexToBytes(hex));

        ECKey pubKey = ECKey.fromPublicOnly(Utils.hexToBytes("033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f4"));
        Script script = new Script(Utils.hexToBytes("56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae"));
        Sha256Hash hash = transaction.hashForWitnessSignature(0, script,987654321L, SigHash.ANYONECANPAY_ALL);
        TransactionSignature signature = TransactionSignature.decodeFromBitcoin(Utils.hexToBytes("3045022100fbefd94bd0a488d50b79102b5dad4ab6ced30c4069f1eaa69a4b5a763414067e02203156c6a5c9cf88f91265f5a942e96213afae16d83321c8b31bb342142a14d16381"), true);
        Assertions.assertTrue(pubKey.verify(hash, signature));
    }

    @Test
    public void verifyP2SHP2WSHSigHashNoneAnyoneCanPay() {
        String hex = "010000000136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000000ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac00000000";
        Transaction transaction = new Transaction(Utils.hexToBytes(hex));

        ECKey pubKey = ECKey.fromPublicOnly(Utils.hexToBytes("03a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac16"));
        Script script = new Script(Utils.hexToBytes("56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae"));
        Sha256Hash hash = transaction.hashForWitnessSignature(0, script,987654321L, SigHash.ANYONECANPAY_NONE);
        TransactionSignature signature = TransactionSignature.decodeFromBitcoin(Utils.hexToBytes("3045022100a5263ea0553ba89221984bd7f0b13613db16e7a70c549a86de0cc0444141a407022005c360ef0ae5a5d4f9f2f87a56c1546cc8268cab08c73501d6b3be2e1e1a8a0882"), true);
        Assertions.assertTrue(pubKey.verify(hash, signature));
    }

    @Test
    public void verifyP2SHP2WSHSigHashSingleAnyoneCanPay() {
        String hex = "010000000136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000000ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac00000000";
        Transaction transaction = new Transaction(Utils.hexToBytes(hex));

        ECKey pubKey = ECKey.fromPublicOnly(Utils.hexToBytes("02d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b"));
        Script script = new Script(Utils.hexToBytes("56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae"));
        Sha256Hash hash = transaction.hashForWitnessSignature(0, script,987654321L, SigHash.ANYONECANPAY_SINGLE);
        TransactionSignature signature = TransactionSignature.decodeFromBitcoin(Utils.hexToBytes("30440220525406a1482936d5a21888260dc165497a90a15669636d8edca6b9fe490d309c022032af0c646a34a44d1f4576bf6a4a74b67940f8faa84c7df9abe12a01a11e2b4783"), true);
        Assertions.assertTrue(pubKey.verify(hash, signature));
    }

    @Test
    public void verifyConstructedTxLengthP2PKH() throws NonStandardScriptException, IOException {
        String hex = "0100000003c07f2ee6dd4e55c6eefdc53659d1fb340beb5eb824d13bc15ba5269ade8de446000000006b483045022100d3f7526a8d1e22233c1f193b63f55406b32010aefeecdc802c07829b583d53a002205f1b666f156433baf6e976b8c43702cfe098e6d6c3c90e4bf2d24eeb1724740a012102faea485f773dbc2f57fe8cf664781a58d499c1f10ad55d370d5b08b92b8ee0c4ffffffffcac7a96d74d8a2b9177c7e0ce735f366d717e759d1f07bbd8a6db55e4b21304e000000006b483045022100d11822be0768c78cdb28ce613051facfa68c6689199505e7d0c75e95b7bd210c02202c5a610ceab38fc6816f6b792c43a1a25ae8507e80cd657dbfecfbff804a455101210287571cbb133887664c47917df7192017906916f7ce470532699c00ae4f10a178ffffffff3b16c58d5d76e119d337a56751b62b60c614ceca73d8e6403476c9e5a74497ab000000006b483045022100cb865e7b13f61f5968a734e0d8257fca72ad6f6b37c80e409e7f986a94f1269d022025e28e140e8087f1804a79b072ae18f69064f53223f2baa169685fe951f16b72012103f23d4fb4ab152b5f6b5e4a0bf79cfcac071c1f2cf07211c8cd176469b2a00628ffffffff02b3070000000000001976a914c3a1a5b559ff4db7f9c92c3d10274a3a18dcea3788ac4be28a00000000001976a914fe0c8a170be39d30f5447e57556e7836ed29e49088ac00000000";
        Transaction parsedTransaction = new Transaction(Utils.hexToBytes(hex));

        Transaction transaction = new Transaction();
        for(TransactionInput txInput : parsedTransaction.getInputs()) {
            transaction.addInput(txInput.getOutpoint().getHash(), txInput.getOutpoint().getIndex(), txInput.getScriptSig());
        }

        for(TransactionOutput txOutput : parsedTransaction.getOutputs()) {
            Address address = txOutput.getScript().getToAddresses()[0];
            transaction.addOutput(txOutput.getValue(), address);
        }

        Assertions.assertEquals(parsedTransaction.getLength(), transaction.getLength());

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transaction.bitcoinSerializeToStream(baos);
        String constructedHex = Utils.bytesToHex(baos.toByteArray());

        Assertions.assertEquals(hex, constructedHex);
    }

    @Test
    public void verifyConstructedTxLengthP2WPKH() throws NonStandardScriptException, IOException {
        String hex = "020000000001014596cc6219630c13cbca099838c2fb0920cde29de1e5473087de8bbce06b9f510100000000ffffffff02502a4b000000000017a914b1cd708c9d49c7ad6ec851ad7f24076233fa7cfb8772915600000000001600145279dddc177883923bcf3bd5aab50e725dca01f302483045022100e9056474685b7d885956c7c7e5ac77e1249373e5d222b13620dcde6a63e337d602206ebb59c1834e991e9c9f6129a78c7669cfc4c41c4d19c6be4dabe6749715d5ee01210278f5f957591a07a51fc5033c3407de2ff722b0a5f98e91c9a9e1e038c9b1b59300000000";
        Transaction parsedTransaction = new Transaction(Utils.hexToBytes(hex));

        Transaction transaction = new Transaction();
        transaction.setVersion(parsedTransaction.getVersion());
        transaction.setSegwitFlag(parsedTransaction.getSegwitFlag());
        for(TransactionInput txInput : parsedTransaction.getInputs()) {
            transaction.addInput(txInput.getOutpoint().getHash(), txInput.getOutpoint().getIndex(), txInput.getScriptSig(), txInput.getWitness());
        }

        for(TransactionOutput txOutput : parsedTransaction.getOutputs()) {
            Address address = txOutput.getScript().getToAddresses()[0];
            transaction.addOutput(txOutput.getValue(), address);
        }

        Assertions.assertEquals(parsedTransaction.getLength(), transaction.getLength());

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transaction.bitcoinSerializeToStream(baos);
        String constructedHex = Utils.bytesToHex(baos.toByteArray());

        Assertions.assertEquals(hex, constructedHex);
    }

    @Test
    public void verifyConstructedTxLengthP2WPKHMulti() throws NonStandardScriptException, IOException {
        String hex = "02000000000102ba4dc5a4a14bfaa941b7d115b379b5e15f960635cf694c178b9116763cbd63b11600000017160014fc164cbcac023f5eacfcead2d17d8768c41949affeffffff074d44d2856beb68ba52e8832da60a1682768c2421c2d9a8109ef4e66babd1fd1e000000171600148c3098be6b430859115f5ee99c84c368afecd0481500400002305310000000000017a914ffaf369c2212b178c7a2c21c9ccdd5d126e74c4187327f0300000000001976a914a7cda2e06b102a143ab606937a01d152e300cd3e88ac02473044022006da0ca227f765179219e08a33026b94e7cacff77f87b8cd8eb1b46d6dda11d6022064faa7912924fd23406b6ed3328f1bbbc3760dc51109a49c1b38bf57029d304f012103c6a2fcd030270427d4abe1041c8af929a9e2dbab07b243673453847ab842ee1f024730440220786316a16095105a0af28dccac5cf80f449dea2ea810a9559a89ecb989c2cb3d02205cbd9913d1217ffec144ae4f2bd895f16d778c2ec49ae9c929fdc8bcc2a2b1db0121024d4985241609d072a59be6418d700e87688f6c4d99a51ad68e66078211f076ee38820900";
        Transaction parsedTransaction = new Transaction(Utils.hexToBytes(hex));

        Transaction transaction = new Transaction();
        transaction.setVersion(parsedTransaction.getVersion());
        transaction.setSegwitFlag(parsedTransaction.getSegwitFlag());
        transaction.setLocktime(parsedTransaction.getLocktime());
        for(TransactionInput txInput : parsedTransaction.getInputs()) {
            TransactionInput newInput = transaction.addInput(txInput.getOutpoint().getHash(), txInput.getOutpoint().getIndex(), txInput.getScriptSig(), txInput.getWitness());
            newInput.setSequenceNumber(txInput.getSequenceNumber());
        }

        for(TransactionOutput txOutput : parsedTransaction.getOutputs()) {
            Address address = txOutput.getScript().getToAddresses()[0];
            transaction.addOutput(txOutput.getValue(), address);
        }

        Assertions.assertEquals(parsedTransaction.getLength(), transaction.getLength());

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transaction.bitcoinSerializeToStream(baos);
        String constructedHex = Utils.bytesToHex(baos.toByteArray());

        Assertions.assertEquals(hex, constructedHex);
    }

    @Test
    public void verifyReconstructedTxP2PK() throws NonStandardScriptException, IOException, InvalidAddressException {
        String spent0Hex = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0804e6ed5b1b02b000ffffffff0100f2052a01000000434104ab3779ba979cd2f7d76fd1b6a57f42bf4bdd9210409a693a46d6d426c0ba021aca2f364ce5141b7721b47fb5f34ce7301abbab24c067048b721c633ae65e1af0ac00000000";
        Transaction spent2Transaction = new Transaction(Utils.hexToBytes(spent0Hex));

        TransactionOutput spent0Output = spent2Transaction.getOutputs().get(0);
        ScriptType spent0ScriptType = ScriptType.getType(spent0Output.getScript());
        Assertions.assertEquals(ScriptType.P2PK, spent0ScriptType);
        ECKey key0 = ECKey.fromPublicOnly(spent0Output.getScript().getChunks().get(0).getData());

        String spendingHex = "010000000183ec1de4385a9617e0ea098ab28936e22757b370c73132028f9d7eed08478db70000000049483045022100c9455b5b385292ca8783201d030ed3e091a56d8bc4f030b7ed1eec20cf9110d2022020b3455f661d466b55cfaae0dbd6e6f861e82f64f225861217b07315167e1b1501ffffffff02005ed0b2000000001976a914aa1cfb996782dfac1b860599d512ed6967e2d25a88ac00943577000000001976a9145fbc2d7b0018d31b5e6628150e5485af17b3fd1988ac00000000";
        Transaction spendingTransaction = new Transaction(Utils.hexToBytes(spendingHex));

        TransactionInput input0 = spendingTransaction.getInputs().get(0);
        TransactionSignature signature0 = input0.getScriptSig().getChunks().get(0).getSignature();

        Transaction transaction = new Transaction();
        spent0ScriptType.addSpendingInput(transaction, spent0Output, key0, signature0);

        transaction.addOutput(3000000000L, Address.fromString("1GWUbNagGsvpwygRCjoczegGVDvpm5fLV8"));
        transaction.addOutput(2000000000L, Address.fromString("19jCd38mHkNcXiGF4AjUCoJBSo7iqqjRHT"));

        Assertions.assertEquals(spendingTransaction.getLength(), transaction.getLength());

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transaction.bitcoinSerializeToStream(baos);
        String constructedHex = Utils.bytesToHex(baos.toByteArray());

        Assertions.assertEquals(spendingHex, constructedHex);
    }

    @Test
    public void verifyReconstructedTxP2PKH() throws NonStandardScriptException, IOException, InvalidAddressException {
        String spent0Hex = "01000000000104923d5f8afc75ec6fafb836b694482ce91a8048c6512ecbbf52e3f9963db5f3000000000023220020d453a61c50faeaa771b9c00f4f6e61d0d38595ca72c614d7533c1650aff3bc24ffffffff5103933b1731e0a5f0b9fce310e27b75638c2951057142dbd984113bce3a5a8000000000232200204394c0daac00d1b6a974adbe592b298c871662931f6a297cde2fa74d3b641df0ffffffff36916f6416d61e320e585798a2f65a4b6ca8ebca640bd7d59a6ad0a83a6ed0bc5e0000002322002082715253072e9e37758b7c65e9b9dd68e21e3ad0559197be5dcfa3d18df8ec3dffffffff404e8656a6f98f00a184b32443ea5b6fd25d8204f8f5ad400e8deb9ae4363de709000000232200208efeaf9ab3d6d8d7c90304a982f67cc61d998ab0e2a4cb236d2dbb4fb2f0a0b5ffffffff60044000000000000017a91482c52f8c8a158a3fbcb0e43caf8103dc81f2e67a872a5a0000000000001976a9141c871707dab7dbb39aed712054b694652d43be7b88ac029200000000000017a9149fa63c45f31746370f4dc428718c5a1a3be49c7e8754d50000000000001976a914e9514a1955b793edf6b0f339211e8e4549ad60d588ac825501000000000017a91453ad08fcb81f1d80f4833c8e27aeb7aaa847cd3287c05701000000000017a9141396a674eab44afb86d46bcca1de2f1e1032593987b36c01000000000017a914c60c91e8a00781fcf55d9f86a31b5c9fd0c6bbd2879cae01000000000017a914d0d18d5e4fd5d59253ac57435e46df6f9039e57b87d5c201000000000017a914cf268163c27b69d15e9b1b64d4d2579e2909db378776eb0100000000001976a91427a45fb91b4f984dce5d10395af0b8a1f7fd42f388acdf610200000000001976a91455b6ee0b10a78292c240bb6376de98816a51049588aca46c0200000000001976a91410c13be439737abc292602d5eb81c3f254fd185288acfc7f02000000000017a9141652910080da8eb88ab327f501aa9d1322263b198767d302000000000017a9140c87f714f9c41b3107d3b7c7b813acb97a8092d3870df10200000000001976a914af12f81b449fb8e1adb0726a4b7bbb942b43dea688aca52a0300000000001976a914eb2beef07bd84514b390df99888ef1b763c9a65b88ac505503000000000017a9143a356b9a43258c0093c7ea2bf64ee3b0cccb4e8b87770004000000000017a914187eb7b8dff49c59d10334b9e6020dc4298668488722010400000000001976a914bc93dbf815ff9d925247b3159db832fb223af56288ac3a4a0400000000001976a91455e71a224f46fb422da845bfbfbedbedbebf6ceb88acc4b404000000000017a914c3aa990232b11bb6ca32b645c81dbe8511e8c7c5877cd904000000000017a9140e6be84ec77846a0f6cbde6b7ff8146793cad4738766ef04000000000017a91420e940dea42c49cb7c579a1266f7d3131c84e1da8766ef04000000000017a9149d56e1f7d4b7c293ab6d2abf03873e6c5fc7c31787061505000000000017a914acbe72dcc22303bac3b2eced921c1eefa290224987ff2f0500000000001976a914767d992989274817207c540d419c0bba95d6304388ac303c0500000000001976a91416963929eacb15be5ab4f1095ea49c1e7f06822e88ac663006000000000017a914d0e9d37cb183f77d404f442e5aa74559282ed76887887306000000000017a914db0439670345fe52363daead83d86fa528e05915870e7c06000000000017a914517a8ef91ed0a7c0c4e6837b17da68823a752e77879faa0600000000001976a914e887836b6491281543e3c9538ea6e5f367f3720b88ac60d80700000000001976a9148629cecb949fae32214c40c560cbf34625796fd288ac29220800000000001976a9141177bbb6bc10c4b121e4d93d44f2907635c5c5b188ac7e7d0800000000001976a91498800085638b60bd6e423e771930e7399926c71788acff7d08000000000017a9140b3a7f22301092e6ca74a9e357b6cc11903667be8719820800000000001976a91450ff7fbaa3115cb55b253ade8f7c08a0a0d8ae5a88acd04e0900000000001976a914924b9ddbf293b0cfeb9e33099ad81e777ecb2f7c88ac80020a000000000017a91455b5ebe096552dbc723d525490a31635a970cbb687e32f0a000000000017a9142f980452bc0d24f3419af297e010d6d66fa2819c87aad10a00000000001976a9147371e5f8991801f14b21ebd2d0361cf4274e506788ac2be90a00000000001976a91441d743c15f84d1f4639f46c963803c7857a43d1288acf8570b000000000017a914f74c8971988af3bc5aea2ab2690a06537c25a3be874c0d0c00000000001976a914576791e848aff210892f8d77f1e6a117519dae9588ac39270c00000000001976a9147761d002ee7737ef8e4e6f50536026602eac92dc88ace97f0d00000000001976a914fe0c8a170be39d30f5447e57556e7836ed29e49088ac04390e000000000017a914418f14799b1eb1234daa82f127b16c199e252a1b87d9a30f00000000001976a91423d7ef491a2bfa1ffe037bc0b837f0b6ee4e0b9f88aca8ea0f000000000017a91464a773d4d2369868256cdb81d1fa89adfc486e6e878eaa1000000000001976a9147ac6256ed9b1c229847dcaae6dd42695e6268ce988aca03213000000000017a914aaca29dda8565eeb203e01796b1ec447a275263187f86d1300000000001976a914f7aa88337662da193390d9b803de6ed8fcde34a188ac9ca21300000000001976a91441a3fddb3cf0580fdc4ea4b14c6a6c147eba56b788ac260114000000000017a914235fe1b23a2f4b7e0b5755adeb752c3244910dfc874f4614000000000017a9148beaa1d290b9365c35478412c983d7eab263950987c05c1500000000001976a9147dd24f287ba2e2a073dea4f53cc9050bcb9aaa0588acc7aa19000000000017a914d7c624671ab3c842648a96333e8e3e2afb28784c871cc51b00000000001976a914e2f3117510024cbe388d7f79fabcb9882c4484eb88ac911b1d00000000001976a9147d87b6e62e9d38a5acc6259115282b548e5bbb4188ac80841e00000000001976a9148f4c957c72beec3caf30d478e343bdf15ac9d6cf88acb5d72200000000001976a914a7bead6dcfd7a49c7a204166a6809c048471615488acf19f23000000000017a914ed61d110dbc8847a385a9cfd08969f994df3606b87f0c823000000000017a914553ec5546e240a01829a2a675680d2f27ef80c39870e172400000000001976a914a6570f223413341e04b47e25d37c6551dbd2115788ac73c42400000000001976a9140b6c529164aa80723c6161bd110c83df8f2ac4c288ace4de2400000000001976a914ea0de4671f149fe2a07e38efd58108b1bb5be22e88ac670226000000000017a914419def84439894f7765dec4874d04ee76a3d29a287ee902700000000001976a9143b020f649d3db57497a4cee4f15a9b804238452a88acb0fa2700000000001976a9149298d7b14ed3eaeee00a288d42607b5cd9beff9a88ac6d422a000000000017a914e6c2a201f5c7836d3055ee56ea40592fdb646d0b877ad02a00000000001976a9143857e125d4a29e08113cef102700634c5872462e88ac4fac31000000000017a9145ca6517ef8e582ef5354a77a29585d2e9702690e8726bd3500000000001976a914f8f8d1621b480a0d4e7d9f9cd314aa6108cc56f788ac7f873d00000000001976a91419288338a36b49192c7a0653d6c8b718df52a4c388acd95f3f00000000001976a914510a35dc572bc2dc55e558fbadc9e31953f7129b88ac80714500000000001976a914738d3394f7944ff1d76146ae856aad5e6841d3d988aca6294c00000000001976a914c1d441fe0168d67acc529a2e71bfdd19416ee62e88ac33034e00000000001976a914c9043264d845f9af61572adff7ad2b48b5cd50d088ac480d5000000000001976a91450a24587b22beb541b7e26b84add27671fd70cad88acc8545300000000001976a9148a77f414a06a9924a220216d8f18a8e25b1c032c88aca80e6900000000001976a9149a327f9ea4d51846ceb2ce78180a7a323061376188ac54c46900000000001976a914b67633d60d7cf4b658762d8bf348b7efe548cf1f88ac9db78800000000001976a914a7046f79031532214dac9e039e9b4823761738d288accde98900000000001976a914a1e65f57a630de0daac04e034f00452ec6385bfc88acc0d8a700000000001976a914a16a6ed6a85826625da49509e13f84316ab8aa5388ac23f4a800000000001976a914dad83b667ec2d442ab2d6296615ff480fbb39bfe88ac793ab600000000001976a9142a178bfe13a9509a69c7b89633adc7be84c2b3ec88acadfec7000000000017a9145022ad489df92d0a200ffadbcf3492f01efc9c0487db0b0601000000001976a91426248841f8d66c680a3a9b9816d53f3af283548e88ac802252010000000017a914640ba152487ba112aa487aea068cf1926475ee9887449ad602000000001976a9148cdad086ad0c8d1b1a265c51e49fe0d9e70e322588ac8d0c0603000000001976a914db8adda60de534cbd97cc2953ab922c521f54a7e88acf0565603000000001976a91438cb3d20424d77a0e1d21efd87579a3511fd537588ac008793030000000017a914b093a97da5eb35a965461bbb093840f72af2dc02877bd57f04000000001976a914edcefefa335223e2770d1f58b5b7e7cc0804366488ace0261706000000001976a91454e07bff6e6d36a6994db0ef54c608f8d66e327888ac8ca1f0200000000017a914fb687a86645e45cbaed8d8be9855c9d20e74c1358704004730440220688e04fbf3ce7e7b8dcefc4785f72a66d23026733a38775f223582555f6a22eb0220174d7fcedbbf61079a0089debf359cd2351bb1d4c2e17b79ea7cee6b0d22b1a70147304402205a863c92db3bb40a6346fb0f24281ad48436c5e52de630d4e349e10a70474c1f02202d9e1e175018d20df00a1ce9bc25f75d0e5865e27a4bcad07ca4e9e543bf3aa601695221027c157c4466a847cc0b01a2b51e23556d87a50ec6f89362a9a54e4e126a8614cb21034738313c53fbe6f63da94c0fdbfaef01084dd8795bc0baf8fb7709eb6241da7221032deae35acbb4eed54c70394f9d998910730f3c331d818106e105e013d264217453ae0400483045022100aaa49821cf736ea9dcbdd9f0ce22ae976381fffa3d49c246c49245ddeee1f95f022018790656b7729e6a29f712875bed98fb350e782bed9cf88ff20876231d5d5fd1014730440220726c9278fc250270a10bebbd482c42407b79270d2198a987410a966c2b451cc702207492185242b9e77004a4ce6227245752c6ef3d4766d48cc5f6c296f8595511660169522102480bfcfb664fbd8fbca04548010348d5334746b7ce87718440f9643430ee10802103a84ee88dbf345c082bb56d241bf7cb25afec6e4b953e3b4cfb2e27a4a58300de210391fa8e55da6f40a9b2a91dfe93b62d029073e0e091a672304345648dcc42f6db53ae0400473044022016426a4aebc58efdcb884ebe8a7d32fb3a1b1efdfcd2858f37b6ec88f7d4fbef02200cbb907cc6aaea6918d876d29c6e9abd6fe9c2dfb551f5095e2ad82a2660c0d1014730440220657801bc58b49b6bc039c5756f6d70ce47e62a004c8648b877ad3848a140d5fe0220581c5c48287454b89f92a37d4137ab67e2880dad51554ae4e887221a28999d5d0169522103dde1b42a6048f133fb417b592694081bbf6b51b994e36283f6f39fde09711aa321025981d800052069c31aeefac1ad8b0d0e451ce3248da5ffa41dbc0c21bcb26a1021026718ceaaadeb67721ebd532423a4f104e15c459a80d0bd363519cf3817d8be7953ae040047304402201b56739ea79145c320661a2f08811cb5d2f67b997c2078f4026b7ff0427819c9022045d69bd5a32592f1f1bf777a484bc20a1707a84b7036350128d9eee95638eb1d0147304402206c06e360814eb38391eaa14ed3dab6bb2d14987360d47a6685f4a2447518be2f02205d858969353c2c28233a4e15d3c010a7a9d0e884c17eec51ae50c8023a3beb5601695221036bb06e224c197c532e8cd67de05bcf331b00f692712625ba2de12d5afc5087c82103da6890cd195f4468dd976aa664edf90c151dc488fe4ee2ee041a98c5069c730b210265b884234c0b305f8c2af4b724adb8db1c160cd1d081d62a84afe6939e036d1453aeeeb80900";
        Transaction spent2Transaction = new Transaction(Utils.hexToBytes(spent0Hex));

        TransactionOutput spent0Output = spent2Transaction.getOutputs().get(44);
        ScriptType spent0ScriptType = ScriptType.getType(spent0Output.getScript());
        Assertions.assertEquals(ScriptType.P2PKH, spent0ScriptType);

        String spent1Hex = "0100000003c07f2ee6dd4e55c6eefdc53659d1fb340beb5eb824d13bc15ba5269ade8de446000000006b483045022100d3f7526a8d1e22233c1f193b63f55406b32010aefeecdc802c07829b583d53a002205f1b666f156433baf6e976b8c43702cfe098e6d6c3c90e4bf2d24eeb1724740a012102faea485f773dbc2f57fe8cf664781a58d499c1f10ad55d370d5b08b92b8ee0c4ffffffffcac7a96d74d8a2b9177c7e0ce735f366d717e759d1f07bbd8a6db55e4b21304e000000006b483045022100d11822be0768c78cdb28ce613051facfa68c6689199505e7d0c75e95b7bd210c02202c5a610ceab38fc6816f6b792c43a1a25ae8507e80cd657dbfecfbff804a455101210287571cbb133887664c47917df7192017906916f7ce470532699c00ae4f10a178ffffffff3b16c58d5d76e119d337a56751b62b60c614ceca73d8e6403476c9e5a74497ab000000006b483045022100cb865e7b13f61f5968a734e0d8257fca72ad6f6b37c80e409e7f986a94f1269d022025e28e140e8087f1804a79b072ae18f69064f53223f2baa169685fe951f16b72012103f23d4fb4ab152b5f6b5e4a0bf79cfcac071c1f2cf07211c8cd176469b2a00628ffffffff02b3070000000000001976a914c3a1a5b559ff4db7f9c92c3d10274a3a18dcea3788ac4be28a00000000001976a914fe0c8a170be39d30f5447e57556e7836ed29e49088ac00000000";
        Transaction spentTransaction = new Transaction(Utils.hexToBytes(spent1Hex));

        TransactionOutput spent1Output = spentTransaction.getOutputs().get(1);
        ScriptType spent1ScriptType = ScriptType.getType(spent1Output.getScript());
        Assertions.assertEquals(ScriptType.P2PKH, spent1ScriptType);

        String spendingHex = "010000000250d5218b2ff43b067dc11c06565d9bcf075aae26b392c4a29b673db6cffe94002c0000006b483045022100f0d5cea0874c38da6ae9e680486475cdf0267e8e316c23c390841b798f0e3cfe022043dea019c74ec6fed0126cbe18d6f7e72ad470222c5a6b3fc9369c99d9bdf8130121021fcbb2abcfd113f7e89a9d9ff4fce381dfd25e9d22d6d418839c00fa5316706fffffffff1985042874e037fbb0bb9e2ecc2dc2bab548b16d948c521e445c840a94c01f84010000006b483045022100918445e440fc81b2c42f658003b9b04a9be80200d22432e863b290b604ad1bea022032c21eaaea7a27b795dda03b2f3affb65347d929dfd32a8f12d1d459deda0cd10121021fcbb2abcfd113f7e89a9d9ff4fce381dfd25e9d22d6d418839c00fa5316706fffffffff029a030000000000001976a914bfefdae17b75487c1af143eed457a40a5bb2c44388ac385a9800000000001976a914fd76c43a0a3e4652ddb1832956959082d39aa72188ac00000000";
        Transaction spendingTransaction = new Transaction(Utils.hexToBytes(spendingHex));

        TransactionInput input0 = spendingTransaction.getInputs().get(0);
        TransactionSignature signature0 = input0.getScriptSig().getChunks().get(0).getSignature();
        ECKey pubKey0 = input0.getScriptSig().getChunks().get(1).getPubKey();

        TransactionInput input1 = spendingTransaction.getInputs().get(1);
        TransactionSignature signature1 = input1.getScriptSig().getChunks().get(0).getSignature();
        ECKey pubKey1 = input1.getScriptSig().getChunks().get(1).getPubKey();

        Transaction transaction = new Transaction();
        spent0ScriptType.addSpendingInput(transaction, spent0Output, pubKey0, signature0);
        spent1ScriptType.addSpendingInput(transaction, spent1Output, pubKey1, signature1);

        transaction.addOutput(922, Address.fromString("1JVsQ4L4HAcn58Gj5uF16dvgFNdVTarY6i"));
        transaction.addOutput(9984568, Address.fromString("1Q7CEaM3CQ6ejGHgDZNbdTTAkoLcPk63nQ"));

        Assertions.assertEquals(spendingTransaction.getLength(), transaction.getLength());

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transaction.bitcoinSerializeToStream(baos);
        String constructedHex = Utils.bytesToHex(baos.toByteArray());

        Assertions.assertEquals(spendingHex, constructedHex);
    }

    @Test
    public void verifyReconstructedTxP2SH() throws NonStandardScriptException, IOException, InvalidAddressException {
        String spent0Hex = "01000000013192d32076c7d60729f2eca05fd60d40887fe332421be0e828b188efb95b3e7c010000006a4730440220456662aff60c92d20e9e16ee01b6ea8748ef1b4720a858134d0ee038c83df8c70220464905dd25c1cd97833495a8101d7c0e5d0eb5edc9f7619fa14a2117ad92d116012103c144e864600c155326e0925844aace78fe424abbb8c00a0ce7d7e9ae13da7e95ffffffff02c8a67b490000000017a91432a81641354091c480fe29a64324ece273ed669487c2895ea8220000001976a914359fcea57940deaa62db92f65394e973ba25310288ac00000000";
        Transaction spent2Transaction = new Transaction(Utils.hexToBytes(spent0Hex));

        TransactionOutput spent0Output = spent2Transaction.getOutputs().get(0);
        ScriptType spent0ScriptType = ScriptType.getType(spent0Output.getScript());
        Assertions.assertEquals(ScriptType.P2SH, spent0ScriptType);

        String spendingHex = "010000000166de02f10de096b3939f683bd1ff226ff216348df73cef884b6bbc853546600400000000fc0047304402204a66f038d6132bfebc692b5f23b8ce37165e8edd73e626f161bc69d0261aeec2022073afbf11c86538529221ea2eef95edc04159267d81a244bd15d3bd401e5ece05014730440220702644ef148ae4cd5f59679c0bd80ea44ed215dc42f75c2a8903bac126c7f36202201307e47ffd91dcc739ab670bbb1f6f22b5b468dbd058f937dd5b089d8dc4855d014c695221036973b3bedc40371520fa12bb165920fec7a4a842309f46c287d217794cde1f5b2103cc30b5a2c8b6e3ac18e6d8871c57b2e71030eee1167f1e0b0e11362d86e8f9632103da8b609d639d4dbb9490ab93e9f4de09bf969d2017dfe6925ac56abd541a0a5d53aeffffffff0414b70c000000000017a91400d0a158647216d83ad60659ac32b0a040990092878090dd48000000001976a9147c4898213f9741cb0cee70fd96844ee4eb67f19a88ace0100500000000001976a9146ec61f16216725bbc9d85509147a5fc5044d3da088ac343c89000000000017a914f41f1fcd0c35a20e23fb92c59b632bbcf7dc563c8700000000";
        Transaction spendingTransaction = new Transaction(Utils.hexToBytes(spendingHex));

        TransactionInput input0 = spendingTransaction.getInputs().get(0);
        TransactionSignature signature0 = input0.getScriptSig().getChunks().get(1).getSignature();
        TransactionSignature signature1 = input0.getScriptSig().getChunks().get(2).getSignature();
        Script redeemScript = new Script(input0.getScriptSig().getChunks().get(3).getData());
        ECKey key0 = redeemScript.getChunks().get(1).getPubKey();
        ECKey key1 = redeemScript.getChunks().get(2).getPubKey();
        ECKey key2 = redeemScript.getChunks().get(3).getPubKey();

        Map<ECKey, TransactionSignature> pubKeySignatures = new TreeMap<>(new ECKey.LexicographicECKeyComparator());
        pubKeySignatures.put(key0, signature0);
        pubKeySignatures.put(key1, signature1);
        pubKeySignatures.put(key2, null);

        Transaction transaction = new Transaction();
        spent0ScriptType.addMultisigSpendingInput(transaction, spent0Output, 2, pubKeySignatures);

        transaction.addOutput(833300, Address.fromString("31mKrRn3xQoGppLY5dU92Dbm4kN4ddkknE"));
        transaction.addOutput(1222480000, Address.fromString("1CL9kj1seXif6agPfeh6vpKkzc2Hxq1UpM"));
        transaction.addOutput(332000, Address.fromString("1B6ifpYaSvBkjJTf4W1tjYgDYajFua3NU8"));
        transaction.addOutput(8993844, Address.fromString("3Pwp5u7PwgrMw3gAAyLAkDKYKRrFuFkneG"));

        Assertions.assertEquals(spendingTransaction.getLength(), transaction.getLength());

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transaction.bitcoinSerializeToStream(baos);
        String constructedHex = Utils.bytesToHex(baos.toByteArray());

        Assertions.assertEquals(spendingHex, constructedHex);
    }

    @Test
    public void verifyReconstructedTxP2SHP2WPKH() throws NonStandardScriptException, IOException, InvalidAddressException {
        String spent0Hex = "010000000001014e6120e50f876635a088f825793487fc0467722dbddef14ca31ae3a88aef1fc901000000171600148edd09d1117175a77cf9d58e1cb9c96430903979fdffffff03a00f0000000000001976a914d83f1dc836e701d17b8adf2c5e9726a4af8078b088ac4e6a00000000000017a91450dab4502ba8881856259a45611e0e9d859e1b4787026206000000000017a914c8bfc88770631bfcee814b3524abba965bf7be048702483045022100c8deb4e97dec5a0107ca124a05f6484a107c7bf9c6d9ddc50b0b2ff4a7a9f632022040390473e032b9d5f38fe777c209bac820d804800ae0494bf7fd938eb8fd8a3f012102ada4557d88d3d7130bd7b28cc06397ed91d2a1d49d4280f08c76b7b947b769b600000000";
        Transaction spent2Transaction = new Transaction(Utils.hexToBytes(spent0Hex));

        TransactionOutput spent0Output = spent2Transaction.getOutputs().get(2);
        ScriptType spent0ScriptType = ScriptType.getType(spent0Output.getScript());
        Assertions.assertEquals(ScriptType.P2SH, spent0ScriptType);

        String spendingHex = "01000000000101e0a6a25fd728d9b755b4329acf66ae5f264e1bba763487b91410c36c85fb6e3802000000171600148edd09d1117175a77cf9d58e1cb9c96430903979fdffffff03a00f0000000000001976a914d83f1dc836e701d17b8adf2c5e9726a4af8078b088acf68205000000000017a914054e8b8fcd56228d18a4b3d4cc550cbad5f0c6a387dc6900000000000017a914c8bfc88770631bfcee814b3524abba965bf7be048702483045022100b6ecb3e7d4f607cc495bac79e2d5cf999cc347a51751b90e50505bf1a9153dcc02203bd844375f01183e7d08d90c6c18118dc8ac6b3686e5a22ec9a39205f632482b012102ada4557d88d3d7130bd7b28cc06397ed91d2a1d49d4280f08c76b7b947b769b600000000";
        Transaction spendingTransaction = new Transaction(Utils.hexToBytes(spendingHex));

        TransactionInput input0 = spendingTransaction.getInputs().get(0);
        Script spendingScript = input0.getScriptSig();
        TransactionWitness witness0 = input0.getWitness();
        TransactionSignature signature0 = TransactionSignature.decodeFromBitcoin(witness0.getPushes().get(0), false);
        ECKey pubKey0 = ECKey.fromPublicOnly(witness0.getPushes().get(1));

        Transaction transaction = new Transaction();
        transaction.setSegwitFlag(1);
        TransactionInput input = ScriptType.P2SH_P2WPKH.addSpendingInput(transaction, spent0Output, pubKey0, signature0);
        input.setSequenceNumber(TransactionInput.SEQUENCE_RBF_ENABLED);

        transaction.addOutput(4000, Address.fromString("1LiQZqSwPqb615uyxDKTaN9Tg4CER98cgJ"));
        transaction.addOutput(361206, Address.fromString("32B5Pv7Nvhh8iQ3Z2xK8cbKBW5f2bGMoqp"));
        transaction.addOutput(27100, Address.fromString("3KzUpFMVKXiNETUy19VVW9Re5EimboDuyX"));

        Assertions.assertEquals(spendingTransaction.getLength(), transaction.getLength());

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transaction.bitcoinSerializeToStream(baos);
        String constructedHex = Utils.bytesToHex(baos.toByteArray());

        Assertions.assertEquals(spendingHex, constructedHex);
    }

    @Test
    public void verifyReconstructedTxP2SHP2WSH() throws NonStandardScriptException, IOException, InvalidAddressException {
        String spent0Hex = "01000000000101e5e980b4cdcf1371a376d2f0a010f4e7de5d5691ec3b5ca998a2c2f6abab4a010600000023220020ef9feb56ba03b174c538bff1012cbb5e5c0d6100041a052adae09a9aa8d8b3b7ffffffff08601e8d030000000017a9141f1022d6732f39ee94ef3290e3f39a514d2e682187a07af1020000000017a914054fa6cad6486e64397190993903d3eb78e972eb87d0444c030000000017a91472c12c9b5dc4212a06c6e2be1768f6f08d2a69818720f734040000000017a914c8b38cd3262587cbf68690f53cf6f724d8f0c5e58740418f030000000017a9149e2de724b9b098ce75b92ee7331bea20b9a03416878026f8010000000017a9149d3ef266c162ddbb293d742001e0cc6390ae33a487802fa6040000000017a914603b0822693eb8934450653b2d77bb18a63958b987308ed5020000000017a914de706829f776b5b1139dc1b53360406c500538a5870400473044022070c435849751a32a816ec89d51126cc9798dbdfaafd571e6fa6aa8f8995bc30f0220337b86ea3f665b315717d920c4cf24c82b7877e843b504e15a8b00cb994a095e01473044022044b44dad3343e63abf7a23da234eeb6b828645248808d438cdb383fe5edc00e702205aa1f75369f3a87e5e0602f709076e6efa775d49c714e82bb26fa97e486cd3550169522103cdb6712a28c70ace204f817bcfa2296c81662bb7544c4e5595b80dfc58c01cad2102305242866430b4525a9ee53f2d010229347c201c3011d247ef847d9ed3a712a82102ae9b4d93708835ec02854732366ccedcf756b789082bd9802a5c66ba33fbda1453ae00000000";
        Transaction spent2Transaction = new Transaction(Utils.hexToBytes(spent0Hex));

        TransactionOutput spent0Output = spent2Transaction.getOutputs().get(0);
        ScriptType spent0ScriptType = ScriptType.getType(spent0Output.getScript());
        Assertions.assertEquals(ScriptType.P2SH, spent0ScriptType);

        String spendingHex = "0100000000010168f3192941dda765f281d15f6402c16d9401ad5230eba8ed49f4caf63c00bf060000000023220020358b2d04e290b58d3481f9c4c019564c8c04046e4c4c333fc9672d838cb51856ffffffff0285a788030000000017a914ebc8d73588f7eae589d7c42b7a22af7215de9e24875b3e03000000000017a914c281f1d0c58168df144c7299f4e0c0e4281bf62c870400483045022100989e8a8dda2ba3a319bd6aa96a7cef12578000c70c67388e151da769b8be32c4022015c4de148ed129c80a538427a2c94e02743635badc3877a84f59c9142f7aa1a701473044022044cc31cff2af4d11f2fc9351dee3a06cd7407716cd5b72cf98176d336499ed5e02203e0e9c34ca94b68a64fd4f72d67d7f089f8b1fbe21fa05380bcd082736ade3c401695221025d7f3fc74bec54e0c62a50af262e465b9416047fda49f4257e0fda16250242272103b4021db115bae8fc9ce5c80de5d2c07f2ff76a41b1b8de828f9009f48547788d2103bff31daad67be914b8d65e3af52448ab897164d61c170849e28fc94e676cf1cb53ae00000000";
        Transaction spendingTransaction = new Transaction(Utils.hexToBytes(spendingHex));

        TransactionInput input0 = spendingTransaction.getInputs().get(0);
        TransactionWitness witness0 = input0.getWitness();
        TransactionSignature signature0 = TransactionSignature.decodeFromBitcoin(witness0.getPushes().get(1), false);
        TransactionSignature signature1 = TransactionSignature.decodeFromBitcoin(witness0.getPushes().get(2), false);
        Script witnessScript = new Script(witness0.getPushes().get(3));
        ECKey key0 = witnessScript.getChunks().get(1).getPubKey();
        ECKey key1 = witnessScript.getChunks().get(2).getPubKey();
        ECKey key2 = witnessScript.getChunks().get(3).getPubKey();

        Map<ECKey, TransactionSignature> pubKeySignatures = new TreeMap<>(new ECKey.LexicographicECKeyComparator());
        pubKeySignatures.put(key0, signature0);
        pubKeySignatures.put(key1, signature1);
        pubKeySignatures.put(key2, null);

        Transaction transaction = new Transaction();
        transaction.setSegwitFlag(1);
        TransactionInput input = ScriptType.P2SH_P2WSH.addMultisigSpendingInput(transaction, spent0Output, 2, pubKeySignatures);

        transaction.addOutput(59287429, Address.fromString("3PBjKH4FRuEKy4sD3NfL7tqfZTG5K42owu"));
        transaction.addOutput(212571, Address.fromString("3KRUgU4XGuErXkjBtFhksPzTGJ4AMwF4jB"));

        Assertions.assertEquals(spendingTransaction.getLength(), transaction.getLength());

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transaction.bitcoinSerializeToStream(baos);
        String constructedHex = Utils.bytesToHex(baos.toByteArray());

        Assertions.assertEquals(spendingHex, constructedHex);
    }

    @Test
    public void verifyReconstructedTxP2WPKH() throws NonStandardScriptException, IOException, InvalidAddressException {
        String spent0Hex = "02000000000101ba704c9e8a5981f2b2682312bf3632a3d4f99c5d6ee7dbf8f8135804459890730100000000ffffffff02be71b80c000000001600142db5decf53c76ecfc3ee3ba95909872fad4a0aefcfb81600000000001976a91429418cb34cec93a0a9f3bcd81ff1550cbdca002e88ac02473044022004c576c0f1cddc2d85a2e6ea620f051790415155d88e05d859b9f9347751963c02204a31f40a03f9da9b6a0f763b3ad852576383c74ceb4ed9549c198f37fc4b19b6012103fda72b0f00ba00675b1bc911c40e3fb708bb64548b79b6497e11b243c46f46ab00000000";
        Transaction spent2Transaction = new Transaction(Utils.hexToBytes(spent0Hex));

        TransactionOutput spent0Output = spent2Transaction.getOutputs().get(0);
        ScriptType spent0ScriptType = ScriptType.getType(spent0Output.getScript());
        Assertions.assertEquals(ScriptType.P2WPKH, spent0ScriptType);

        String spendingHex = "020000000001017ea85b784c10a639517cc2d8ed4f5dcc261149aed9efc379ce66b9baed1259b70000000000ffffffff02de879c0c000000001600142db5decf53c76ecfc3ee3ba95909872fad4a0aef7b8f1b000000000017a914f85d965a9244e89bdb1925d62a9fd06b602b8962870247304402203a00ecd77a3051e924cc5a42b7b023a5abb17aea00365be49a75a5f5d9057c8702201e889ece99b24b8d44d63b4d727e40c88882d98adee937af9e4543f52de79ac8012103fda72b0f00ba00675b1bc911c40e3fb708bb64548b79b6497e11b243c46f46ab00000000";
        Transaction spendingTransaction = new Transaction(Utils.hexToBytes(spendingHex));

        TransactionInput input0 = spendingTransaction.getInputs().get(0);
        TransactionWitness witness0 = input0.getWitness();
        TransactionSignature signature0 = TransactionSignature.decodeFromBitcoin(witness0.getPushes().get(0), false);
        ECKey key0 = ECKey.fromPublicOnly(witness0.getPushes().get(1));

        Transaction transaction = new Transaction();
        transaction.setVersion(2);
        transaction.setSegwitFlag(1);
        spent0ScriptType.addSpendingInput(transaction, spent0Output, key0, signature0);

        transaction.addOutput(211584990, Address.fromString("bc1q9k6aan6ncahvlslw8w54jzv897k55zh077un6s"));
        transaction.addOutput(1806203, Address.fromString("3QLFcgKFNzo262FYRFgGfrUNiUurpQbDZv"));

        Assertions.assertEquals(spendingTransaction.getLength(), transaction.getLength());

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transaction.bitcoinSerializeToStream(baos);
        String constructedHex = Utils.bytesToHex(baos.toByteArray());

        Assertions.assertEquals(spendingHex, constructedHex);
    }

    @Test
    public void verifyReconstructedTxP2WSH() throws NonStandardScriptException, IOException, InvalidAddressException {
        String spent0Hex = "01000000000101275f4973ebc66a9d44b0196ec33820ad29ee32bef55899f2e322782740afd55d0500000000ffffffff06001bb7000000000017a914f065c662326faa3acd1226817f5f48f3d9748afd87b9ca1e000000000017a9149d19a31ef45bf46dee11974dcf6253c287a5fa7d8780f0fa020000000017a914a1475b36de36df9b8bb484fdc27ce051ef04115887ea42ee000000000017a91479e90530f4ecdae0ce59bf6dc9a7260240a656da8700c2eb0b000000001976a9145e1eb0472895a56375936e9bbc851ff0239acc9d88acab71cf1d00000000220020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d040047304402204226aa74970340e5f2b63f8a70081624df42fac85f75217794fc047f6173fa6602200f534a6948767d79f0d9980dfe0bf8fccac17726fec7a1dfe8a4b42eda19ae080147304402201be0ad255f70d7944d0019e62bfa68da7b97b292c6e17419e3fc203a50eac81e0220604e6467257f623e3d3fcec718725c33b13d3445bc70aed719c04e429bd52efe016952210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae00000000";
        Transaction spent2Transaction = new Transaction(Utils.hexToBytes(spent0Hex));

        TransactionOutput spent0Output = spent2Transaction.getOutputs().get(5);
        ScriptType spent0ScriptType = ScriptType.getType(spent0Output.getScript());
        Assertions.assertEquals(ScriptType.P2WSH, spent0ScriptType);

        String spendingHex = "01000000000101b892f0a74954a730bc3e8a5a4341a144fc43dce4d9c2bc97dbdb13c501b067690500000000ffffffff032052a6000000000017a91485b5696f13edb4e9b2ac68f0de7a3e26e65c7c4e87208cd113000000001976a914c6872477e0d3f4bbd73cbaf4b9134f4204205e3888ac2bf7560900000000220020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d040047304402205599051161390edd68d8ed01535a64f8f5d53f7418e73838c6fd6513670a095602200d7846aecf92765f4aa26da0f519f86d7b00cd29b9d43b8d73644a53975b94440147304402205cea311a37eb62219a75d4e05b513afd80a448b59caae99d4a9a3029d55dfd8d0220134656a5bcc2c5ec27c0f6e14f9e9212b0d5ca838fc7e5ac3699f8953fdafaf5016952210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae00000000";
        Transaction spendingTransaction = new Transaction(Utils.hexToBytes(spendingHex));

        TransactionInput input0 = spendingTransaction.getInputs().get(0);
        TransactionWitness witness0 = input0.getWitness();
        TransactionSignature signature0 = TransactionSignature.decodeFromBitcoin(witness0.getPushes().get(1), false);
        TransactionSignature signature1 = TransactionSignature.decodeFromBitcoin(witness0.getPushes().get(2), false);
        Script witnessScript = new Script(witness0.getPushes().get(3));
        ECKey key0 = witnessScript.getChunks().get(1).getPubKey();
        ECKey key1 = witnessScript.getChunks().get(2).getPubKey();
        ECKey key2 = witnessScript.getChunks().get(3).getPubKey();

        Map<ECKey, TransactionSignature> pubKeySignatures = new TreeMap<>(new ECKey.LexicographicECKeyComparator());
        pubKeySignatures.put(key0, signature0);
        pubKeySignatures.put(key1, signature1);
        pubKeySignatures.put(key2, null);

        Transaction transaction = new Transaction();
        transaction.setSegwitFlag(1);
        spent0ScriptType.addMultisigSpendingInput(transaction, spent0Output, 2, pubKeySignatures);

        transaction.addOutput(10900000, Address.fromString("3Dt17mpd8FDXBjP56rCD7a4Sx7wpL91uhn"));
        transaction.addOutput(332500000, Address.fromString("1K6igqzm36x8jxRTavPhgWXLVcVZVDTGc9"));
        transaction.addOutput(156694315, Address.fromString("bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej"));

        Assertions.assertEquals(spendingTransaction.getLength(), transaction.getLength());

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transaction.bitcoinSerializeToStream(baos);
        String constructedHex = Utils.bytesToHex(baos.toByteArray());

        Assertions.assertEquals(spendingHex, constructedHex);
    }

    @Test
    public void signBip340() {
        ECKey privKey = ECKey.fromPrivate(Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000003"));
        Assertions.assertEquals("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9", Utils.bytesToHex(privKey.getPubKeyXCoord()).toUpperCase(Locale.ROOT));
        SchnorrSignature sig = privKey.signSchnorr(Sha256Hash.ZERO_HASH);
        Assertions.assertEquals("E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0", Utils.bytesToHex(sig.encode()).toUpperCase(Locale.ROOT));
    }

    @Test
    public void signTaprootKeypath() {
        Transaction tx = new Transaction(Utils.hexToBytes("02000000000101786ed355f998b98f8ef8ef2acf461577325cf170a9133d48a17aba957eb97ff00000000000ffffffff0100e1f50500000000220020693a94699e6e41ab302fd623a9bf5a5b2d6606cbfb35c550d1cb4300451356a102473044022004cc317c20eb9e372cb0e640f51eb2b8311616125321b11dbaa5671db5a3ca2a02207ae3d2771b565be98ae56e21045b9629c94b6ca8f4e3932260e54d4f0e2016b30121032da1692a41a61ad14f3795b31d33431abf8d6ee161b997d004c26a37bc20083500000000"));
        Transaction spendingTx = new Transaction(Utils.hexToBytes("01000000011af4dca4a6bc6da092edca5390355891da9bbe76d2be1c04d067ec9c3a3d22b10000000000000000000180f0fa0200000000160014a3bcb5f272025cc66dc42e7518a5846bd60a9c9600000000"));

        Sha256Hash hash = spendingTx.hashForTaprootSignature(tx.getOutputs(), 0, false, null, SigHash.DEFAULT, null);
        ECKey privateKey = ECKey.fromPrivate(Utils.hexToBytes("d9bc817b92916a24b87d25dc48ef466b4fcd6c89cf90afbc17cba40eb8b91330"));
        SchnorrSignature sig = privateKey.signSchnorr(hash);

        Assertions.assertEquals("7b04f59bc8f5c2c33c9b8acbf94743de74cc25a6052b52ff61a516f7c5ca19cc68345ba99b354f22bfaf5c04de395b9223f3bf0a5c351fc1cc68c224f4e5b202", Utils.bytesToHex(sig.encode()));

        ECKey pubKey = ECKey.fromPublicOnly(privateKey);
        Assertions.assertTrue(pubKey.verify(hash, new TransactionSignature(sig, SigHash.DEFAULT)));
    }
}
