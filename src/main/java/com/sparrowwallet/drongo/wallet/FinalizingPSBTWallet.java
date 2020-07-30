package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.policy.Miniscript;
import com.sparrowwallet.drongo.policy.Policy;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.protocol.TransactionSignature;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.psbt.PSBTInput;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * This is a special wallet that is used solely to finalize a fully signed PSBT by reading from the partial signatures and UTXO scriptPubKey
 *
 */
public class FinalizingPSBTWallet extends Wallet {
    private final Map<PSBTInput, WalletNode> signedInputNodes = new LinkedHashMap<>();
    private final Map<WalletNode, List<ECKey>> signedNodeKeys = new LinkedHashMap<>();
    private int numSignatures;

    public FinalizingPSBTWallet(PSBT psbt) {
        super("Finalizing PSBT Wallet");

        Map<PSBTInput, WalletNode> signingNodes = new LinkedHashMap<>();
        for(int i = 0; i < psbt.getPsbtInputs().size(); i++) {
            PSBTInput psbtInput = psbt.getPsbtInputs().get(i);
            Set<ECKey> keys = psbtInput.getPartialSignatures().keySet();
            WalletNode signedNode = new WalletNode("m/" + i);
            signedInputNodes.put(psbtInput, signedNode);
            signedNodeKeys.put(signedNode, new ArrayList<>(keys));
            numSignatures = keys.size();
            setScriptType(ScriptType.getType(psbtInput.getUtxo().getScript()));
        }

        setPolicyType(numSignatures == 1 ? PolicyType.SINGLE : PolicyType.MULTI);
    }

    @Override
    public Map<PSBTInput, List<Keystore>> getSignedKeystores(PSBT psbt) {
        Map<PSBTInput, List<Keystore>> signedKeystores = new LinkedHashMap<>();
        for(PSBTInput psbtInput : psbt.getPsbtInputs()) {
            Collection<TransactionSignature> signatures = psbtInput.getSignatures();
            signedKeystores.put(psbtInput, IntStream.range(1, signatures.size() + 1).mapToObj(i -> new Keystore("Keystore " + i)).collect(Collectors.toList()));
        }
        return signedKeystores;
    }

    @Override
    public Policy getDefaultPolicy() {
        return new Policy(new Miniscript("")) {
            @Override
            public int getNumSignaturesRequired() {
                return numSignatures;
            }
        };
    }

    @Override
    public Map<PSBTInput, WalletNode> getSigningNodes(PSBT psbt) {
        return signedInputNodes;
    }

    @Override
    public ECKey getPubKey(WalletNode node) {
        return signedNodeKeys.get(node).get(0);
    }

    @Override
    public List<ECKey> getPubKeys(WalletNode node) {
        return signedNodeKeys.get(node);
    }
}