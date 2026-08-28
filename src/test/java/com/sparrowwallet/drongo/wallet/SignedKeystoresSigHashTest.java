package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.KeyPurpose;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.policy.Policy;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.*;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Map;

/**
 * getSignedKeystores(Transaction) recomputes the signature hash to work out which keystore produced a
 * signature. It uses a fixed hash type rather than the one the signature carries, so a transaction
 * signed with anything other than ALL is reported as signed by nobody.
 */
public class SignedKeystoresSigHashTest {
    private static final String MNEMONIC = "absent essay fox snake vast pumpkin height crouch silent bulb excuse razor";
    private static final long FUNDING_VALUE = 100_000_000L;

    private Wallet wallet() throws Exception {
        Wallet wallet = new Wallet();
        wallet.setPolicyType(PolicyType.SINGLE_HD);
        wallet.setScriptType(ScriptType.P2WPKH);
        DeterministicSeed seed = new DeterministicSeed(MNEMONIC, "", 0, DeterministicSeed.Type.BIP39);
        wallet.getKeystores().add(Keystore.fromSeed(seed, PolicyType.SINGLE_HD, wallet.getScriptType().getDefaultDerivation()));
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE_HD, ScriptType.P2WPKH, wallet.getKeystores(), 1));
        wallet.getNode(KeyPurpose.RECEIVE);
        return wallet;
    }

    /**
     * Signs one wallet input with the given hash type and returns the finished transaction, with the
     * funding transaction recorded on the wallet so the spent output can be found.
     */
    private Transaction spendWith(Wallet wallet, SigHash sigHash) throws Exception {
        WalletNode node = wallet.getNode(KeyPurpose.RECEIVE).getChildren().iterator().next();
        Script spk = wallet.getOutputScript(node);

        Transaction funding = new Transaction();
        funding.addInput(Sha256Hash.ZERO_HASH, 0, new Script(new byte[0]));
        funding.addOutput(FUNDING_VALUE, spk);
        wallet.updateTransactions(Map.of(funding.getTxId(),
                new BlockTransaction(funding.getTxId(), 1, null, null, funding)));

        Transaction spending = new Transaction();
        spending.setVersion(2);
        spending.addInput(funding.getTxId(), 0, new Script(new byte[0]));
        spending.addOutput(FUNDING_VALUE - 10_000, spk);

        ECKey key = wallet.getKeystores().getFirst().getKey(node);
        Script scriptCode = ScriptType.P2PKH.getOutputScript(key.getPubKeyHash());
        Sha256Hash hash = spending.hashForWitnessSignature(0, scriptCode, FUNDING_VALUE, sigHash);
        TransactionSignature signature = key.sign(hash, sigHash, TransactionSignature.Type.ECDSA);
        spending.getInputs().getFirst().setWitness(new TransactionWitness(spending, key, signature));
        return spending;
    }

    @Test
    public void testASigHashAllSignatureIsAttributed() throws Exception {
        Wallet wallet = wallet();
        Map<TransactionInput, Map<TransactionSignature, Keystore>> signed =
                wallet.getSignedKeystores(spendWith(wallet, SigHash.ALL));
        Assertions.assertEquals(1, signed.values().stream().mapToInt(Map::size).sum(),
                "A signature made with ALL must be attributed to the keystore that made it");
    }

    /**
     * A signature parsed off the wire can carry flags that are not a defined hash type. Those cannot have
     * come from a key here, so they should be passed over rather than aborting the whole lookup.
     */
    @Test
    public void testAnUndefinedHashTypeIsSkipped() throws Exception {
        Wallet wallet = wallet();
        Transaction transaction = spendWith(wallet, SigHash.ALL);
        WalletNode node = wallet.getNode(KeyPurpose.RECEIVE).getChildren().iterator().next();
        //0x7f is not a hash type SigHash defines; the components do not need to verify for this
        TransactionSignature undefined = new TransactionSignature(BigInteger.ONE, BigInteger.TWO,
                TransactionSignature.Type.ECDSA, (byte)0x7f);
        transaction.getInputs().getFirst().setWitness(new TransactionWitness(transaction,
                wallet.getKeystores().getFirst().getKey(node), undefined));

        Assertions.assertDoesNotThrow(() -> wallet.getSignedKeystores(transaction),
                "An undefined hash type must not abort the lookup");
    }

    @Test
    public void testASigHashSingleSignatureIsAttributed() throws Exception {
        Wallet wallet = wallet();
        Map<TransactionInput, Map<TransactionSignature, Keystore>> signed =
                wallet.getSignedKeystores(spendWith(wallet, SigHash.SINGLE));
        Assertions.assertEquals(1, signed.values().stream().mapToInt(Map::size).sum(),
                "A signature made with SINGLE must be attributed too; the hash type is on the signature");
    }
}
