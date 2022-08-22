package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.KeyPurpose;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.policy.Miniscript;
import com.sparrowwallet.drongo.policy.Policy;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.*;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.psbt.PSBTInput;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * This is a special wallet that is used solely to finalize a fully signed PSBT by reading from the partial signatures and UTXO scriptPubKey
 * It is used when the normal wallet is not available, for example when the wallet file is kept in an offline only setting
 */
public class FinalizingPSBTWallet extends Wallet {
    private final Map<PSBTInput, WalletNode> signedInputNodes = new LinkedHashMap<>();
    private final Map<WalletNode, List<ECKey>> signedNodeKeys = new LinkedHashMap<>();
    private int numSignatures;

    public FinalizingPSBTWallet(PSBT psbt) {
        super("Finalizing PSBT Wallet");

        if(!psbt.isSigned()) {
            throw new IllegalArgumentException("Only a fully signed or finalized PSBT can be used");
        }

        WalletNode purposeNode = getNode(KeyPurpose.RECEIVE);
        List<WalletNode> signedNodes = new ArrayList<>(purposeNode.getChildren());

        for(int i = 0; i < psbt.getPsbtInputs().size(); i++) {
            PSBTInput psbtInput = psbt.getPsbtInputs().get(i);
            Set<ECKey> keys = psbtInput.getPartialSignatures().keySet();

            WalletNode signedNode = signedNodes.get(i);
            signedInputNodes.put(psbtInput, signedNode);
            signedNodeKeys.put(signedNode, new ArrayList<>(keys));

            ScriptType scriptType = psbtInput.getScriptType();
            if(scriptType == null || (getScriptType() != null && !scriptType.equals(getScriptType()))) {
                throw new IllegalArgumentException("Cannot determine the script type from the PSBT, or there are multiple script types");
            } else {
                setScriptType(scriptType);
            }

            try {
                Script signingScript = psbtInput.getSigningScript();
                int sigsRequired = signingScript.getNumRequiredSignatures();
                if(numSignatures > 0 && sigsRequired != numSignatures) {
                    throw new IllegalArgumentException("Different number of signatures required in PSBT inputs");
                } else {
                    numSignatures = sigsRequired;
                }

                if(ScriptType.MULTISIG.isScriptType(signingScript)) {
                    signedNodeKeys.put(signedNode, Arrays.asList(ScriptType.MULTISIG.getPublicKeysFromScript(signingScript)));
                }
            } catch(NonStandardScriptException e) {
                throw new IllegalArgumentException(e.getMessage());
            }
        }

        setGapLimit(0);
        purposeNode.setChildren(new TreeSet<>());

        setPolicyType(numSignatures == 1 ? PolicyType.SINGLE : PolicyType.MULTI);
    }

    @Override
    public Map<PSBTInput, Map<TransactionSignature, Keystore>> getSignedKeystores(PSBT psbt) {
        Map<PSBTInput, Map<TransactionSignature, Keystore>> signedKeystores = new LinkedHashMap<>();
        for(PSBTInput psbtInput : psbt.getPsbtInputs()) {
            List<TransactionSignature> signatures = new ArrayList<>(psbtInput.getSignatures());
            Map<TransactionSignature, Keystore> signatureKeystoreMap = new LinkedHashMap<>();
            for(int i = 0; i < signatures.size(); i++) {
                signatureKeystoreMap.put(signatures.get(i), new Keystore("Keystore " + (i + 1)));
            }
            signedKeystores.put(psbtInput, signatureKeystoreMap);
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

    @Override
    public Script getOutputScript(WalletNode node) {
        for(Map.Entry<PSBTInput, WalletNode> entry : signedInputNodes.entrySet()) {
            if(node.equals(entry.getValue())) {
                return entry.getKey().getUtxo().getScript();
            }
        }

        return new Script(new byte[10]);
    }

    @Override
    public boolean canSign(PSBT psbt) {
        return !getSigningNodes(psbt).isEmpty();
    }

    @Override
    public boolean isWalletTxo(TransactionInput txInput) {
        for(PSBTInput psbtInput : signedInputNodes.keySet()) {
            TransactionInput psbtTxInput = psbtInput.getInput();
            if(psbtTxInput.getOutpoint().getHash().equals(txInput.getOutpoint().getHash()) && psbtTxInput.getOutpoint().getIndex() == txInput.getOutpoint().getIndex()) {
                return true;
            }
        }

        return false;
    }
}