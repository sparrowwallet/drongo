package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.BitcoinUnit;
import com.sparrowwallet.drongo.KeyPurpose;
import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.address.Address;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.crypto.Key;
import com.sparrowwallet.drongo.policy.Policy;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.*;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.psbt.PSBTInput;

import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

import static com.sparrowwallet.drongo.protocol.ScriptType.*;
import static com.sparrowwallet.drongo.protocol.Transaction.WITNESS_SCALE_FACTOR;

public class Wallet {
    public static final int DEFAULT_LOOKAHEAD = 20;
    public static final String ALLOW_DERIVATIONS_MATCHING_OTHER_SCRIPT_TYPES_PROPERTY = "com.sparrowwallet.allowDerivationsMatchingOtherScriptTypes";

    private String name;
    private Network network = Network.get();
    private PolicyType policyType;
    private ScriptType scriptType;
    private Policy defaultPolicy;
    private List<Keystore> keystores = new ArrayList<>();
    private final TreeSet<WalletNode> purposeNodes = new TreeSet<>();
    private final Map<Sha256Hash, BlockTransaction> transactions = new HashMap<>();
    private Integer storedBlockHeight;
    private Integer gapLimit;
    private Date birthDate;

    public Wallet() {
    }

    public Wallet(String name) {
        this.name = name;
    }

    public Wallet(String name, PolicyType policyType, ScriptType scriptType) {
        this(name, policyType, scriptType, null);
    }

    public Wallet(String name, PolicyType policyType, ScriptType scriptType, Date birthDate) {
        this.name = name;
        this.policyType = policyType;
        this.scriptType = scriptType;
        this.birthDate = birthDate;
        this.keystores = Collections.singletonList(new Keystore());
        this.defaultPolicy = Policy.getPolicy(policyType, scriptType, keystores, null);
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Network getNetwork() {
        return network;
    }

    public void setNetwork(Network network) {
        this.network = network;
    }

    public PolicyType getPolicyType() {
        return policyType;
    }

    public void setPolicyType(PolicyType policyType) {
        this.policyType = policyType;
    }

    public ScriptType getScriptType() {
        return scriptType;
    }

    public void setScriptType(ScriptType scriptType) {
        this.scriptType = scriptType;
    }

    public Policy getDefaultPolicy() {
        return defaultPolicy;
    }

    public void setDefaultPolicy(Policy defaultPolicy) {
        this.defaultPolicy = defaultPolicy;
    }

    public List<Keystore> getKeystores() {
        return keystores;
    }

    public Map<Sha256Hash, BlockTransaction> getTransactions() {
        return Collections.unmodifiableMap(transactions);
    }

    public synchronized void updateTransactions(Map<Sha256Hash, BlockTransaction> updatedTransactions) {
        for(BlockTransaction blockTx : updatedTransactions.values()) {
            Optional<String> optionalLabel = transactions.values().stream().filter(oldBlTx -> oldBlTx.getHash().equals(blockTx.getHash())).map(BlockTransaction::getLabel).filter(Objects::nonNull).findFirst();
            optionalLabel.ifPresent(blockTx::setLabel);
        }

        transactions.putAll(updatedTransactions);

        if(!transactions.isEmpty()) {
            birthDate = transactions.values().stream().map(BlockTransactionHash::getDate).filter(Objects::nonNull).min(Date::compareTo).orElse(birthDate);
        }
    }

    public Integer getStoredBlockHeight() {
        return storedBlockHeight;
    }

    public void setStoredBlockHeight(Integer storedBlockHeight) {
        this.storedBlockHeight = storedBlockHeight;
    }

    public int getGapLimit() {
        return gapLimit == null ? DEFAULT_LOOKAHEAD : gapLimit;
    }

    public void setGapLimit(int gapLimit) {
        this.gapLimit = gapLimit;
    }

    public Date getBirthDate() {
        return birthDate;
    }

    public void setBirthDate(Date birthDate) {
        this.birthDate = birthDate;
    }

    public synchronized WalletNode getNode(KeyPurpose keyPurpose) {
        WalletNode purposeNode;
        Optional<WalletNode> optionalPurposeNode = purposeNodes.stream().filter(node -> node.getKeyPurpose().equals(keyPurpose)).findFirst();
        if(optionalPurposeNode.isEmpty()) {
            purposeNode = new WalletNode(keyPurpose);
            purposeNodes.add(purposeNode);
        } else {
            purposeNode = optionalPurposeNode.get();
        }

        purposeNode.fillToIndex(getLookAheadIndex(purposeNode));
        return purposeNode;
    }

    public int getLookAheadIndex(WalletNode node) {
        int lookAheadIndex = getGapLimit() - 1;
        Integer highestUsed = node.getHighestUsedIndex();
        if(highestUsed != null) {
            lookAheadIndex = highestUsed + getGapLimit();
        }

        return lookAheadIndex;
    }

    public WalletNode getFreshNode(KeyPurpose keyPurpose) {
        return getFreshNode(keyPurpose, null);
    }

    public WalletNode getFreshNode(KeyPurpose keyPurpose, WalletNode current) {
        int index = 0;

        WalletNode node = getNode(keyPurpose);
        Integer highestUsed = node.getHighestUsedIndex();
        if(highestUsed != null) {
            index = highestUsed + 1;
        }

        if(current != null && current.getIndex() >= index) {
            index = current.getIndex() + 1;
        }

        if(index >= node.getChildren().size()) {
            node.fillToIndex(index);
        }

        for(WalletNode childNode : node.getChildren()) {
            if(childNode.getIndex() == index) {
                return childNode;
            }
        }

        throw new IllegalStateException("Could not fill nodes to index " + index);
    }

    public ECKey getPubKey(WalletNode node) {
        return getPubKey(node.getKeyPurpose(), node.getIndex());
    }

    public ECKey getPubKey(KeyPurpose keyPurpose, int index) {
        if(policyType == PolicyType.MULTI) {
            throw new IllegalStateException("Attempting to retrieve a single key for a multisig policy wallet");
        } else if(policyType == PolicyType.CUSTOM) {
            throw new UnsupportedOperationException("Cannot determine a public key for a custom policy");
        }

        Keystore keystore = getKeystores().get(0);
        return keystore.getPubKey(keyPurpose, index);
    }

    public List<ECKey> getPubKeys(WalletNode node) {
        return getPubKeys(node.getKeyPurpose(), node.getIndex());
    }

    public List<ECKey> getPubKeys(KeyPurpose keyPurpose, int index) {
        if(policyType == PolicyType.SINGLE) {
            throw new IllegalStateException("Attempting to retrieve multiple keys for a singlesig policy wallet");
        } else if(policyType == PolicyType.CUSTOM) {
            throw new UnsupportedOperationException("Cannot determine public keys for a custom policy");
        }

        return getKeystores().stream().map(keystore -> keystore.getPubKey(keyPurpose, index)).collect(Collectors.toList());
    }

    public Address getAddress(WalletNode node) {
        return getAddress(node.getKeyPurpose(), node.getIndex());
    }

    public Address getAddress(KeyPurpose keyPurpose, int index) {
        if(policyType == PolicyType.SINGLE) {
            ECKey pubKey = getPubKey(keyPurpose, index);
            return scriptType.getAddress(pubKey);
        } else if(policyType == PolicyType.MULTI) {
            List<ECKey> pubKeys = getPubKeys(keyPurpose, index);
            Script script = ScriptType.MULTISIG.getOutputScript(defaultPolicy.getNumSignaturesRequired(), pubKeys);
            return scriptType.getAddress(script);
        } else {
            throw new UnsupportedOperationException("Cannot determine addresses for custom policies");
        }
    }

    public Script getOutputScript(WalletNode node) {
        return getOutputScript(node.getKeyPurpose(), node.getIndex());
    }

    public Script getOutputScript(KeyPurpose keyPurpose, int index) {
        if(policyType == PolicyType.SINGLE) {
            ECKey pubKey = getPubKey(keyPurpose, index);
            return scriptType.getOutputScript(pubKey);
        } else if(policyType == PolicyType.MULTI) {
            List<ECKey> pubKeys = getPubKeys(keyPurpose, index);
            Script script = ScriptType.MULTISIG.getOutputScript(defaultPolicy.getNumSignaturesRequired(), pubKeys);
            return scriptType.getOutputScript(script);
        } else {
            throw new UnsupportedOperationException("Cannot determine output script for custom policies");
        }
    }

    public String getOutputDescriptor(WalletNode node) {
        return getOutputDescriptor(node.getKeyPurpose(), node.getIndex());
    }

    public String getOutputDescriptor(KeyPurpose keyPurpose, int index) {
        if(policyType == PolicyType.SINGLE) {
            ECKey pubKey = getPubKey(keyPurpose, index);
            return scriptType.getOutputDescriptor(pubKey);
        } else if(policyType == PolicyType.MULTI) {
            List<ECKey> pubKeys = getPubKeys(keyPurpose, index);
            Script script = ScriptType.MULTISIG.getOutputScript(defaultPolicy.getNumSignaturesRequired(), pubKeys);
            return scriptType.getOutputDescriptor(script);
        } else {
            throw new UnsupportedOperationException("Cannot determine output descriptor for custom policies");
        }
    }

    public boolean isWalletAddress(Address address) {
        return getWalletAddresses().containsKey(address);
    }

    public Map<Address, WalletNode> getWalletAddresses() {
        Map<Address, WalletNode> walletAddresses = new LinkedHashMap<>();
        getWalletAddresses(walletAddresses, getNode(KeyPurpose.RECEIVE));
        getWalletAddresses(walletAddresses, getNode(KeyPurpose.CHANGE));
        return walletAddresses;
    }

    private void getWalletAddresses(Map<Address, WalletNode> walletAddresses, WalletNode purposeNode) {
        for(WalletNode addressNode : purposeNode.getChildren()) {
            walletAddresses.put(getAddress(addressNode), addressNode);
        }
    }

    public boolean isWalletOutputScript(Script outputScript) {
        return getWalletOutputScripts().containsKey(outputScript);
    }

    public Map<Script, WalletNode> getWalletOutputScripts() {
        return getWalletOutputScripts(KeyPurpose.RECEIVE, KeyPurpose.CHANGE);
    }

    public Map<Script, WalletNode> getWalletOutputScripts(KeyPurpose... keyPurposes) {
        Map<Script, WalletNode> walletOutputScripts = new LinkedHashMap<>();
        for(KeyPurpose keyPurpose : keyPurposes) {
            getWalletOutputScripts(walletOutputScripts, getNode(keyPurpose));
        }
        return walletOutputScripts;
    }

    private void getWalletOutputScripts(Map<Script, WalletNode> walletOutputScripts, WalletNode purposeNode) {
        for(WalletNode addressNode : purposeNode.getChildren()) {
            walletOutputScripts.put(getOutputScript(addressNode), addressNode);
        }
    }

    public boolean isWalletTxo(BlockTransactionHashIndex txo) {
        return getWalletTxos().containsKey(txo);
    }

    public Map<BlockTransactionHashIndex, WalletNode> getWalletTxos() {
        Map<BlockTransactionHashIndex, WalletNode> walletTxos = new TreeMap<>();
        getWalletTxos(walletTxos, getNode(KeyPurpose.RECEIVE));
        getWalletTxos(walletTxos, getNode(KeyPurpose.CHANGE));
        return walletTxos;
    }

    private void getWalletTxos(Map<BlockTransactionHashIndex, WalletNode> walletTxos, WalletNode purposeNode) {
        for(WalletNode addressNode : purposeNode.getChildren()) {
            for(BlockTransactionHashIndex txo : addressNode.getTransactionOutputs()) {
                walletTxos.put(txo, addressNode);
            }
        }
    }

    public Map<BlockTransactionHashIndex, WalletNode> getWalletUtxos() {
        return getWalletUtxos(false);
    }

    public Map<BlockTransactionHashIndex, WalletNode> getWalletUtxos(boolean includeSpentMempoolOutputs) {
        Map<BlockTransactionHashIndex, WalletNode> walletUtxos = new TreeMap<>();
        getWalletUtxos(walletUtxos, getNode(KeyPurpose.RECEIVE), includeSpentMempoolOutputs);
        getWalletUtxos(walletUtxos, getNode(KeyPurpose.CHANGE), includeSpentMempoolOutputs);
        return walletUtxos;
    }

    private void getWalletUtxos(Map<BlockTransactionHashIndex, WalletNode> walletUtxos, WalletNode purposeNode, boolean includeSpentMempoolOutputs) {
        for(WalletNode addressNode : purposeNode.getChildren()) {
            for(BlockTransactionHashIndex utxo : addressNode.getUnspentTransactionOutputs(includeSpentMempoolOutputs)) {
                walletUtxos.put(utxo, addressNode);
            }
        }
    }

    /**
     * Determines the dust threshold for creating a new change output in this wallet.
     *
     * @param output The output under consideration
     * @param feeRate The fee rate for the transaction creating the change UTXO
     * @return the minimum viable value than the provided change output must have in order to not be dust
     */
    public long getDustThreshold(TransactionOutput output, Double feeRate) {
        return getFee(output, feeRate, Transaction.DUST_RELAY_TX_FEE);
    }

    /**
     * Determines the minimum incremental fee necessary to pay for added the provided output to a transaction
     * This is done by calculating the sum of multiplying the size of the output at the current fee rate,
     * and the size of the input needed to spend it in future at the long term fee rate
     *
     * @param output The output to be added
     * @param feeRate The transaction's fee rate
     * @param longTermFeeRate The long term minimum fee rate
     * @return The fee that adding this output would add
     */
    public long getFee(TransactionOutput output, Double feeRate, Double longTermFeeRate) {
        //Start with length of output
        int outputVbytes = output.getLength();
        //Add length of spending input (with or without discount depending on script type)
        int inputVbytes = getInputVbytes();

        //Return fee rate in sats/vbyte multiplied by the calculated output and input vByte lengths
        return (long)(feeRate * outputVbytes + longTermFeeRate * inputVbytes);
    }

    /**
     * Determines the fee for a transaction from this wallet that has one output and no inputs
     *
     * @param payments The payment details to create the output to send to
     * @return The determined fee
     */
    public long getNoInputsFee(List<Payment> payments, Double feeRate) {
        return (long)Math.ceil((double)getNoInputsWeightUnits(payments) * feeRate / (double)WITNESS_SCALE_FACTOR);
    }

    /**
     * Determines the weight units for a transaction from this wallet that has one output and no inputs
     *
     * @param payments The payment details to create the output to send to
     * @return The determined weight units
     */
    public int getNoInputsWeightUnits(List<Payment> payments) {
        Transaction transaction = new Transaction();
        if(Arrays.asList(ScriptType.WITNESS_TYPES).contains(getScriptType())) {
            transaction.setSegwitVersion(0);
        }
        for(Payment payment : payments) {
            transaction.addOutput(payment.getAmount(), payment.getAddress());
        }
        return transaction.getWeightUnits();
    }

    /**
     * Return the number of vBytes required for an input created by this wallet.
     *
     * @return the number of vBytes
     */
    public int getInputVbytes() {
        return (int)Math.ceil((double)getInputWeightUnits() / (double)WITNESS_SCALE_FACTOR);
    }

    /**
     * Return the number of weight units required for an input created by this wallet.
     *
     * @return the number of weight units (WU)
     */
    public int getInputWeightUnits() {
        //Estimate assuming an input spending from a fresh receive node - it does not matter this node has no real utxos
        WalletNode receiveNode = getFreshNode(KeyPurpose.RECEIVE);

        Transaction transaction = new Transaction();
        TransactionOutput prevTxOut = transaction.addOutput(1L, getAddress(receiveNode));

        TransactionInput txInput = null;
        if(getPolicyType().equals(PolicyType.SINGLE)) {
            ECKey pubKey = getPubKey(receiveNode);
            TransactionSignature signature = TransactionSignature.dummy();
            txInput = getScriptType().addSpendingInput(transaction, prevTxOut, pubKey, signature);
        } else if(getPolicyType().equals(PolicyType.MULTI)) {
            List<ECKey> pubKeys = getPubKeys(receiveNode);
            int threshold = getDefaultPolicy().getNumSignaturesRequired();
            Map<ECKey, TransactionSignature> pubKeySignatures = new TreeMap<>(new ECKey.LexicographicECKeyComparator());
            for(int i = 0; i < pubKeys.size(); i++) {
                pubKeySignatures.put(pubKeys.get(i), i < threshold ? TransactionSignature.dummy() : null);
            }
            txInput = getScriptType().addMultisigSpendingInput(transaction, prevTxOut, threshold, pubKeySignatures);
        }

        assert txInput != null;
        int wu = txInput.getLength() * WITNESS_SCALE_FACTOR;
        if(txInput.hasWitness()) {
            wu += txInput.getWitness().getLength();
        }

        return wu;
    }

    public long getCostOfChange(double feeRate, double longTermFeeRate) {
        WalletNode changeNode = getFreshNode(KeyPurpose.CHANGE);
        TransactionOutput changeOutput = new TransactionOutput(new Transaction(), 1L, getOutputScript(changeNode));
        return getFee(changeOutput, feeRate, longTermFeeRate);
    }

    public WalletTransaction createWalletTransaction(List<UtxoSelector> utxoSelectors, List<UtxoFilter> utxoFilters, List<Payment> payments, double feeRate, double longTermFeeRate, Long fee, Integer currentBlockHeight, boolean groupByAddress, boolean includeMempoolOutputs, boolean includeSpentMempoolOutputs) throws InsufficientFundsException {
        boolean sendMax = payments.stream().anyMatch(Payment::isSendMax);
        long totalPaymentAmount = payments.stream().map(Payment::getAmount).mapToLong(v -> v).sum();
        long totalUtxoValue = getWalletUtxos().keySet().stream().mapToLong(BlockTransactionHashIndex::getValue).sum();

        if(fee != null && feeRate != Transaction.DEFAULT_MIN_RELAY_FEE) {
            throw new IllegalArgumentException("Use an input fee rate of 1 sat/vB when using a defined fee amount so UTXO selectors overestimate effective value");
        }

        long maxSpendableAmt = getMaxSpendable(payments.stream().map(Payment::getAddress).collect(Collectors.toList()), feeRate);
        if(maxSpendableAmt < 0) {
            throw new InsufficientFundsException("Not enough combined value in all available UTXOs to send a transaction to the provided addresses at this fee rate");
        }

        //When a user fee is set, we can calculate the fees to spend all UTXOs because we assume all UTXOs are spendable at a fee rate of 1 sat/vB
        //We can then add the user set fee less this amount as a "phantom payment amount" to the value required to find (which cannot include transaction fees)
        long valueRequiredAmt = totalPaymentAmount + (fee != null ? fee - (totalUtxoValue - maxSpendableAmt) : 0);
        if(maxSpendableAmt < valueRequiredAmt) {
            throw new InsufficientFundsException("Not enough combined value in all available UTXOs to send a transaction to send the provided payments at the user set fee" + (fee == null ? " rate" : ""));
        }

        while(true) {
            Map<BlockTransactionHashIndex, WalletNode> selectedUtxos = selectInputs(utxoSelectors, utxoFilters, valueRequiredAmt, feeRate, longTermFeeRate, groupByAddress, includeMempoolOutputs, includeSpentMempoolOutputs, sendMax);
            long totalSelectedAmt = selectedUtxos.keySet().stream().mapToLong(BlockTransactionHashIndex::getValue).sum();

            Transaction transaction = new Transaction();
            transaction.setVersion(2);
            if(currentBlockHeight != null) {
                transaction.setLocktime(currentBlockHeight.longValue());
            }

            //Add inputs
            for(Map.Entry<BlockTransactionHashIndex, WalletNode> selectedUtxo : selectedUtxos.entrySet()) {
                Transaction prevTx = getTransactions().get(selectedUtxo.getKey().getHash()).getTransaction();
                TransactionOutput prevTxOut = prevTx.getOutputs().get((int)selectedUtxo.getKey().getIndex());
                TransactionInput txInput = addDummySpendingInput(transaction, selectedUtxo.getValue(), prevTxOut);

                //Enable opt-in RBF by default, matching Bitcoin Core and Electrum
                txInput.setSequenceNumber(TransactionInput.SEQUENCE_RBF_ENABLED);
            }

            //Add recipient outputs
            for(Payment payment : payments) {
                transaction.addOutput(payment.getAmount(), payment.getAddress());
            }

            double noChangeVSize = transaction.getVirtualSize();
            long noChangeFeeRequiredAmt = (fee == null ? (long)Math.floor(feeRate * noChangeVSize) : fee);

            //Add 1 satoshi to accommodate longer signatures when feeRate equals default min relay fee to ensure fee is sufficient
            noChangeFeeRequiredAmt = (fee == null && feeRate == Transaction.DEFAULT_MIN_RELAY_FEE ? noChangeFeeRequiredAmt + 1 : noChangeFeeRequiredAmt);

            //If sending all selected utxos, set the recipient amount to equal to total of those utxos less the no change fee
            long maxSendAmt = totalSelectedAmt - noChangeFeeRequiredAmt;

            Optional<Payment> optMaxPayment = payments.stream().filter(Payment::isSendMax).findFirst();
            if(optMaxPayment.isPresent()) {
                Payment maxPayment = optMaxPayment.get();
                maxSendAmt = maxSendAmt - payments.stream().filter(payment -> !maxPayment.equals(payment)).map(Payment::getAmount).mapToLong(v -> v).sum();
                if(maxSendAmt > 0 && maxPayment.getAmount() != maxSendAmt) {
                    maxPayment.setAmount(maxSendAmt);
                    totalPaymentAmount = payments.stream().map(Payment::getAmount).mapToLong(v -> v).sum();
                    continue;
                }
            }

            //Calculate what is left over from selected utxos after paying recipient
            long differenceAmt = totalSelectedAmt - totalPaymentAmount;

            //If insufficient fee, increase value required from inputs to include the fee and try again
            if(differenceAmt < noChangeFeeRequiredAmt) {
                valueRequiredAmt = totalSelectedAmt + 1;
                //If we haven't selected all UTXOs yet, don't require more than the max spendable amount
                if(valueRequiredAmt > maxSpendableAmt && transaction.getInputs().size() < getWalletUtxos().size()) {
                    valueRequiredAmt =  maxSpendableAmt;
                }

                continue;
            }

            //Determine if a change output is required by checking if its value is greater than its dust threshold
            long changeAmt = differenceAmt - noChangeFeeRequiredAmt;
            double noChangeFeeRate = (fee == null ? feeRate : noChangeFeeRequiredAmt / transaction.getVirtualSize());
            long costOfChangeAmt = getCostOfChange(noChangeFeeRate, longTermFeeRate);
            if(changeAmt > costOfChangeAmt) {
                //Change output is required, determine new fee once change output has been added
                WalletNode changeNode = getFreshNode(KeyPurpose.CHANGE);
                TransactionOutput changeOutput = new TransactionOutput(transaction, changeAmt, getOutputScript(changeNode));
                double changeVSize = noChangeVSize + changeOutput.getLength();
                long changeFeeRequiredAmt = (fee == null ? (long)Math.floor(feeRate * changeVSize) : fee);
                changeFeeRequiredAmt = (fee == null && feeRate == Transaction.DEFAULT_MIN_RELAY_FEE ? changeFeeRequiredAmt + 1 : changeFeeRequiredAmt);

                //Recalculate the change amount with the new fee
                changeAmt = differenceAmt - changeFeeRequiredAmt;
                if(changeAmt < costOfChangeAmt) {
                    //The new fee has meant that the change output is now dust. We pay too high a fee without change, but change is dust when added. Increase value required from inputs and try again
                    valueRequiredAmt = totalSelectedAmt + 1;
                    continue;
                }

                //Add change output
                transaction.addOutput(changeAmt, getOutputScript(changeNode));

                return new WalletTransaction(this, transaction, utxoSelectors, selectedUtxos, payments, changeNode, changeAmt, changeFeeRequiredAmt);
            }

            return new WalletTransaction(this, transaction, utxoSelectors, selectedUtxos, payments, differenceAmt);
        }
    }

    public TransactionInput addDummySpendingInput(Transaction transaction, WalletNode walletNode, TransactionOutput prevTxOut) {
        if(getPolicyType().equals(PolicyType.SINGLE)) {
            ECKey pubKey = getPubKey(walletNode);
            return getScriptType().addSpendingInput(transaction, prevTxOut, pubKey, TransactionSignature.dummy());
        } else if(getPolicyType().equals(PolicyType.MULTI)) {
            List<ECKey> pubKeys = getPubKeys(walletNode);
            int threshold = getDefaultPolicy().getNumSignaturesRequired();
            Map<ECKey, TransactionSignature> pubKeySignatures = new TreeMap<>(new ECKey.LexicographicECKeyComparator());
            for(int i = 0; i < pubKeys.size(); i++) {
                pubKeySignatures.put(pubKeys.get(i), i < threshold ? TransactionSignature.dummy() : null);
            }
            return getScriptType().addMultisigSpendingInput(transaction, prevTxOut, threshold, pubKeySignatures);
        } else {
            throw new UnsupportedOperationException("Cannot create transaction for policy type " + getPolicyType());
        }
    }

    private Map<BlockTransactionHashIndex, WalletNode> selectInputs(List<UtxoSelector> utxoSelectors, List<UtxoFilter> utxoFilters, Long targetValue, double feeRate, double longTermFeeRate, boolean groupByAddress, boolean includeMempoolOutputs, boolean includeSpentMempoolOutputs, boolean sendMax) throws InsufficientFundsException {
        List<OutputGroup> utxoPool = getGroupedUtxos(utxoFilters, feeRate, longTermFeeRate, groupByAddress, includeSpentMempoolOutputs);

        List<OutputGroup.Filter> filters = new ArrayList<>();
        filters.add(new OutputGroup.Filter(1, 6));
        filters.add(new OutputGroup.Filter(1, 1));
        if(includeMempoolOutputs) {
            filters.add(new OutputGroup.Filter(0, 0));
        }

        if(sendMax) {
            Collections.reverse(filters);
        }

        for(OutputGroup.Filter filter : filters) {
            List<OutputGroup> filteredPool = utxoPool.stream().filter(filter::isEligible).collect(Collectors.toList());

            for(UtxoSelector utxoSelector : utxoSelectors) {
                Collection<BlockTransactionHashIndex> selectedInputs = utxoSelector.select(targetValue, filteredPool);
                long total = selectedInputs.stream().mapToLong(BlockTransactionHashIndex::getValue).sum();
                if(total > targetValue) {
                    Map<BlockTransactionHashIndex, WalletNode> utxos = getWalletUtxos(includeSpentMempoolOutputs);
                    utxos.keySet().retainAll(selectedInputs);
                    return utxos;
                }
            }
        }

        throw new InsufficientFundsException("Not enough combined value in UTXOs for output value " + targetValue);
    }

    private List<OutputGroup> getGroupedUtxos(List<UtxoFilter> utxoFilters, double feeRate, double longTermFeeRate, boolean groupByAddress, boolean includeSpentMempoolOutputs) {
        List<OutputGroup> outputGroups = new ArrayList<>();
        getGroupedUtxos(outputGroups, getNode(KeyPurpose.RECEIVE), utxoFilters, feeRate, longTermFeeRate, groupByAddress, includeSpentMempoolOutputs);
        getGroupedUtxos(outputGroups, getNode(KeyPurpose.CHANGE), utxoFilters, feeRate, longTermFeeRate, groupByAddress, includeSpentMempoolOutputs);
        return outputGroups;
    }

    private void getGroupedUtxos(List<OutputGroup> outputGroups, WalletNode purposeNode, List<UtxoFilter> utxoFilters, double feeRate, double longTermFeeRate, boolean groupByAddress, boolean includeSpentMempoolOutputs) {
        for(WalletNode addressNode : purposeNode.getChildren()) {
            OutputGroup outputGroup = null;
            for(BlockTransactionHashIndex utxo : addressNode.getUnspentTransactionOutputs(includeSpentMempoolOutputs)) {
                Optional<UtxoFilter> matchedFilter = utxoFilters.stream().filter(utxoFilter -> !utxoFilter.isEligible(utxo)).findAny();
                if(matchedFilter.isPresent()) {
                    continue;
                }

                if(outputGroup == null || !groupByAddress) {
                    outputGroup = new OutputGroup(getStoredBlockHeight(), getInputWeightUnits(), feeRate, longTermFeeRate);
                    outputGroups.add(outputGroup);
                }

                outputGroup.add(utxo, allInputsFromWallet(utxo.getHash()));
            }
        }
    }

    /**
     * Determines if the provided wallet transaction was created from a purely internal transaction
     *
     * @param txId The txid
     * @return Whether the transaction was created entirely from inputs that reference outputs that belong to this wallet
     */
    public boolean allInputsFromWallet(Sha256Hash txId) {
        BlockTransaction utxoBlkTx = getTransactions().get(txId);
        if(utxoBlkTx == null) {
            //Provided txId was not a wallet transaction
            return false;
        }

        for(int i = 0; i < utxoBlkTx.getTransaction().getInputs().size(); i++) {
            TransactionInput utxoTxInput = utxoBlkTx.getTransaction().getInputs().get(i);
            BlockTransaction prevBlkTx = getTransactions().get(utxoTxInput.getOutpoint().getHash());
            if(prevBlkTx == null) {
                return false;
            }

            int index = (int)utxoTxInput.getOutpoint().getIndex();
            TransactionOutput prevTxOut = prevBlkTx.getTransaction().getOutputs().get(index);
            BlockTransactionHashIndex spendingTXI = new BlockTransactionHashIndex(utxoBlkTx.getHash(), utxoBlkTx.getHeight(), utxoBlkTx.getDate(), utxoBlkTx.getFee(), i, prevTxOut.getValue());
            BlockTransactionHashIndex spentTXO = new BlockTransactionHashIndex(prevBlkTx.getHash(), prevBlkTx.getHeight(), prevBlkTx.getDate(), prevBlkTx.getFee(), index, prevTxOut.getValue(), spendingTXI);
            if(!isWalletTxo(spentTXO)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Determines the maximum total amount this wallet can send for the number and type of addresses at the given fee rate
     *
     * @param paymentAddresses the addresses to sent to (amounts are irrelevant)
     * @param feeRate the fee rate in sats/vB
     * @return the maximum spendable amount (can be negative if the fee is higher than the combined UTXO value)
     */
    public long getMaxSpendable(List<Address> paymentAddresses, double feeRate) {
        long maxInputValue = 0;
        int inputWeightUnits = getInputWeightUnits();
        long minInputValue = (long)Math.ceil(feeRate * inputWeightUnits / WITNESS_SCALE_FACTOR);

        Transaction transaction = new Transaction();
        for(Map.Entry<BlockTransactionHashIndex, WalletNode> utxo : getWalletUtxos().entrySet()) {
            if(utxo.getKey().getValue() > minInputValue) {
                Transaction prevTx = getTransactions().get(utxo.getKey().getHash()).getTransaction();
                TransactionOutput prevTxOut = prevTx.getOutputs().get((int)utxo.getKey().getIndex());
                addDummySpendingInput(transaction, utxo.getValue(), prevTxOut);
                maxInputValue += utxo.getKey().getValue();
            }
        }

        for(Address address : paymentAddresses) {
            transaction.addOutput(1L, address);
        }

        long fee = (long)Math.floor(transaction.getVirtualSize() * feeRate);
        return maxInputValue - fee;
    }

    public boolean canSign(Transaction transaction) {
        return isValid() && !getSigningNodes(transaction).isEmpty();
    }

    /**
     * Determines which nodes in this wallet can sign which inputs in the provided transaction
     *
     * @param transaction The transaction to be signed, or that has been signed
     * @return A map if the PSBT inputs and the nodes that can sign them
     */
    public Map<TransactionInput, WalletNode> getSigningNodes(Transaction transaction) {
        Map<TransactionInput, WalletNode> signingNodes = new LinkedHashMap<>();
        Map<Script, WalletNode> walletOutputScripts = getWalletOutputScripts();

        for(TransactionInput txInput : transaction.getInputs()) {
            BlockTransaction blockTransaction = transactions.get(txInput.getOutpoint().getHash());
            if(blockTransaction != null && blockTransaction.getTransaction().getOutputs().size() > txInput.getOutpoint().getIndex()) {
                TransactionOutput utxo = blockTransaction.getTransaction().getOutputs().get((int)txInput.getOutpoint().getIndex());

                if(utxo != null) {
                    Script scriptPubKey = utxo.getScript();
                    WalletNode signingNode = walletOutputScripts.get(scriptPubKey);
                    if(signingNode != null) {
                        signingNodes.put(txInput, signingNode);
                    }
                }
            }
        }

        return signingNodes;
    }

    /**
     * Determines which keystores have signed a transaction
     *
     * @param transaction The signed transaction
     * @return A map keyed with the transactionInput mapped to a map of the signatures and associated keystores that signed it
     */
    public Map<TransactionInput, Map<TransactionSignature, Keystore>> getSignedKeystores(Transaction transaction) {
        Map<TransactionInput, WalletNode> signingNodes = getSigningNodes(transaction);
        Map<TransactionInput, Map<TransactionSignature, Keystore>> signedKeystores = new LinkedHashMap<>();

        for(TransactionInput txInput : signingNodes.keySet()) {
            WalletNode walletNode = signingNodes.get(txInput);
            Map<ECKey, Keystore> keystoreKeysForNode = getKeystores().stream().collect(Collectors.toMap(keystore -> keystore.getPubKey(walletNode), Function.identity(),
                    (u, v) -> { throw new IllegalStateException("Duplicate keys from different keystores for node " + walletNode.getDerivationPath()); },
                    LinkedHashMap::new));

            Map<ECKey, TransactionSignature> keySignatureMap = new LinkedHashMap<>();

            BlockTransaction blockTransaction = transactions.get(txInput.getOutpoint().getHash());
            if(blockTransaction != null && blockTransaction.getTransaction().getOutputs().size() > txInput.getOutpoint().getIndex()) {
                TransactionOutput spentTxo = blockTransaction.getTransaction().getOutputs().get((int)txInput.getOutpoint().getIndex());

                Script signingScript = getSigningScript(txInput, spentTxo);
                Sha256Hash hash = txInput.hasWitness() ? transaction.hashForWitnessSignature(txInput.getIndex(), signingScript, spentTxo.getValue(), SigHash.ALL) : transaction.hashForLegacySignature(txInput.getIndex(), signingScript, SigHash.ALL);

                for(ECKey sigPublicKey : keystoreKeysForNode.keySet()) {
                    for(TransactionSignature signature : txInput.hasWitness() ? txInput.getWitness().getSignatures() : txInput.getScriptSig().getSignatures()) {
                        if(sigPublicKey.verify(hash, signature)) {
                            keySignatureMap.put(sigPublicKey, signature);
                        }
                    }
                }

                keystoreKeysForNode.keySet().retainAll(keySignatureMap.keySet());

                Map<TransactionSignature, Keystore> inputSignatureKeystores = new LinkedHashMap<>();
                for(ECKey signingKey : keystoreKeysForNode.keySet()) {
                    inputSignatureKeystores.put(keySignatureMap.get(signingKey), keystoreKeysForNode.get(signingKey));
                }

                signedKeystores.put(txInput, inputSignatureKeystores);
            }
        }

        return signedKeystores;
    }

    private Script getSigningScript(TransactionInput txInput, TransactionOutput spentTxo) {
        Script signingScript = spentTxo.getScript();

        if(P2SH.isScriptType(signingScript)) {
            signingScript = txInput.getScriptSig().getFirstNestedScript();
        }

        if(P2WPKH.isScriptType(signingScript)) {
            signingScript = ScriptType.P2PKH.getOutputScript(signingScript.getPubKeyHash());
        } else if(P2WSH.isScriptType(signingScript) && txInput.hasWitness()) {
            signingScript = txInput.getWitness().getWitnessScript();
        }

        return signingScript;
    }

    public boolean canSign(PSBT psbt) {
        return isValid() && !getSigningNodes(psbt).isEmpty();
    }

    /**
     * Determines which nodes in this wallet can sign which inputs in the provided PSBT
     *
     * @param psbt The PSBT to be signed
     * @return A map if the PSBT inputs and the nodes that can sign them
     */
    public Map<PSBTInput, WalletNode> getSigningNodes(PSBT psbt) {
        Map<PSBTInput, WalletNode> signingNodes = new LinkedHashMap<>();
        Map<Script, WalletNode> walletOutputScripts = getWalletOutputScripts();

        for(PSBTInput psbtInput : psbt.getPsbtInputs()) {
            TransactionOutput utxo = psbtInput.getUtxo();

            if(utxo != null) {
                Script scriptPubKey = utxo.getScript();
                WalletNode signingNode = walletOutputScripts.get(scriptPubKey);
                if(signingNode != null) {
                    signingNodes.put(psbtInput, signingNode);
                }
            }
        }

        return signingNodes;
    }

    /**
     * Determines which keystores have signed a PSBT
     *
     * @param psbt The partially signed or finalized PSBT
     * @return A map keyed with the PSBTInput mapped to a map of the signatures and associated keystores that signed it
     */
    public Map<PSBTInput, Map<TransactionSignature, Keystore>> getSignedKeystores(PSBT psbt) {
        Map<PSBTInput, WalletNode> signingNodes = getSigningNodes(psbt);
        Map<PSBTInput, Map<TransactionSignature, Keystore>> signedKeystores = new LinkedHashMap<>();

        for(PSBTInput psbtInput : signingNodes.keySet()) {
            WalletNode walletNode = signingNodes.get(psbtInput);
            Map<ECKey, Keystore> keystoreKeysForNode = getKeystores().stream().collect(Collectors.toMap(keystore -> keystore.getPubKey(walletNode), Function.identity(),
                    (u, v) -> { throw new IllegalStateException("Duplicate keys from different keystores for node " + walletNode.getDerivationPath()); },
                    LinkedHashMap::new));

            Map<ECKey, TransactionSignature> keySignatureMap;
            if(psbt.isFinalized()) {
                keySignatureMap = psbtInput.getSigningKeys(keystoreKeysForNode.keySet());
            } else {
                keySignatureMap = psbtInput.getPartialSignatures();
            }

            keystoreKeysForNode.keySet().retainAll(keySignatureMap.keySet());

            Map<TransactionSignature, Keystore> inputSignatureKeystores = new LinkedHashMap<>();
            for(ECKey signingKey : keystoreKeysForNode.keySet()) {
                inputSignatureKeystores.put(keySignatureMap.get(signingKey), keystoreKeysForNode.get(signingKey));
            }

            signedKeystores.put(psbtInput, inputSignatureKeystores);
        }

        return signedKeystores;
    }

    public void sign(PSBT psbt) throws MnemonicException {
        Map<PSBTInput, WalletNode> signingNodes = getSigningNodes(psbt);
        for(Keystore keystore : getKeystores()) {
            if(keystore.hasPrivateKey()) {
                for(Map.Entry<PSBTInput, WalletNode> signingEntry : signingNodes.entrySet()) {
                    ECKey privKey = keystore.getKey(signingEntry.getValue());
                    PSBTInput psbtInput = signingEntry.getKey();

                    if(!psbtInput.isSigned()) {
                        psbtInput.sign(privKey);
                    }
                }
            }
        }
    }

    public void finalise(PSBT psbt) {
        int threshold = getDefaultPolicy().getNumSignaturesRequired();
        Map<PSBTInput, WalletNode> signingNodes = getSigningNodes(psbt);

        for(int i = 0; i < psbt.getTransaction().getInputs().size(); i++) {
            TransactionInput txInput = psbt.getTransaction().getInputs().get(i);
            PSBTInput psbtInput = psbt.getPsbtInputs().get(i);

            if(psbtInput.isFinalized()) {
                continue;
            }

            WalletNode signingNode = signingNodes.get(psbtInput);

            //Transaction parent on PSBT utxo might be null in a witness tx, so get utxo tx hash and utxo index from PSBT tx input
            TransactionOutput utxo = new TransactionOutput(null, psbtInput.getUtxo().getValue(), psbtInput.getUtxo().getScript()) {
                @Override
                public Sha256Hash getHash() {
                    return txInput.getOutpoint().getHash();
                }

                @Override
                public int getIndex() {
                    return (int)txInput.getOutpoint().getIndex();
                }
            };

            if(psbtInput.getPartialSignatures().size() >= threshold && signingNode != null) {
                Transaction transaction = new Transaction();

                TransactionInput finalizedTxInput;
                if(getPolicyType().equals(PolicyType.SINGLE)) {
                    ECKey pubKey = getPubKey(signingNode);
                    TransactionSignature transactionSignature = psbtInput.getPartialSignature(pubKey);
                    if(transactionSignature == null) {
                        throw new IllegalArgumentException("Pubkey of partial signature does not match wallet pubkey");
                    }

                    finalizedTxInput = getScriptType().addSpendingInput(transaction, utxo, pubKey, transactionSignature);
                } else if(getPolicyType().equals(PolicyType.MULTI)) {
                    List<ECKey> pubKeys = getPubKeys(signingNode);

                    Map<ECKey, TransactionSignature> pubKeySignatures = new TreeMap<>(new ECKey.LexicographicECKeyComparator());
                    for(ECKey pubKey : pubKeys) {
                        pubKeySignatures.put(pubKey, psbtInput.getPartialSignature(pubKey));
                    }

                    List<TransactionSignature> signatures = pubKeySignatures.values().stream().filter(Objects::nonNull).collect(Collectors.toList());
                    if(signatures.size() < threshold) {
                        throw new IllegalArgumentException("Pubkeys of partial signatures do not match wallet pubkeys");
                    }

                    finalizedTxInput = getScriptType().addMultisigSpendingInput(transaction, utxo, threshold, pubKeySignatures);
                } else {
                    throw new UnsupportedOperationException("Cannot finalise PSBT for policy type " + getPolicyType());
                }

                psbtInput.setFinalScriptSig(finalizedTxInput.getScriptSig());
                psbtInput.setFinalScriptWitness(finalizedTxInput.getWitness());
                psbtInput.clearNonFinalFields();
            }
        }
    }

    public BitcoinUnit getAutoUnit() {
        for(KeyPurpose keyPurpose : KeyPurpose.values()) {
            for(WalletNode addressNode : getNode(keyPurpose).getChildren()) {
                for(BlockTransactionHashIndex output : addressNode.getTransactionOutputs()) {
                    if(output.getValue() >= BitcoinUnit.getAutoThreshold()) {
                        return BitcoinUnit.BTC;
                    }
                }
            }
        }

        return BitcoinUnit.SATOSHIS;
    }

    public void clearNodes() {
        purposeNodes.clear();
        transactions.clear();
        storedBlockHeight = 0;
    }

    public void clearHistory() {
        for(WalletNode purposeNode : purposeNodes) {
            purposeNode.clearHistory();
        }

        transactions.clear();
        storedBlockHeight = 0;
    }

    public boolean isValid() {
        try {
            checkWallet();
        } catch(InvalidWalletException e) {
            return false;
        }

        return true;
    }

    public void checkWallet() throws InvalidWalletException {
        if(policyType == null) {
            throw new InvalidWalletException("No policy type specified");
        }

        if(scriptType == null) {
            throw new InvalidWalletException("No script type specified");
        }

        if(defaultPolicy == null) {
            throw new InvalidWalletException("No default policy specified");
        }

        if(keystores.isEmpty()) {
            throw new InvalidWalletException("No keystores specified");
        }

        if(!ScriptType.getScriptTypesForPolicyType(policyType).contains(scriptType)) {
            throw new InvalidWalletException("Script type of " + scriptType + " is not valid for a policy type of " + policyType);
        }

        int numSigs;
        try {
            numSigs = defaultPolicy.getNumSignaturesRequired();
        } catch (Exception e) {
            throw new InvalidWalletException("Cannot determine number of required signatures to sign a transaction");
        }

        if(policyType.equals(PolicyType.SINGLE) && (numSigs != 1 || keystores.size() != 1)) {
            throw new InvalidWalletException(policyType + " wallet needs " + numSigs + " and has " + keystores.size() + " keystores");
        }

        if(policyType.equals(PolicyType.MULTI) && (numSigs < 1 || numSigs > keystores.size())) {
            throw new InvalidWalletException(policyType + " wallet needs " + numSigs + " and has " + keystores.size() + " keystores");
        }

        if(containsDuplicateKeystoreLabels()) {
            throw new InvalidWalletException("Wallet keystores have duplicate labels");
        }

        for(Keystore keystore : keystores) {
            try {
                keystore.checkKeystore();
            } catch(InvalidKeystoreException e) {
                throw new InvalidWalletException("Keystore " + keystore.getLabel() + " is invalid (" + e.getMessage() + ")", e);
            }

            if(derivationMatchesAnotherScriptType(keystore.getKeyDerivation().getDerivationPath())) {
                throw new InvalidWalletException("Keystore " + keystore.getLabel() + " derivation of " + keystore.getKeyDerivation().getDerivationPath() + " in " + scriptType.getName() + " wallet matches another default script type.");
            }
        }
    }

    public boolean derivationMatchesAnotherScriptType(String derivationPath) {
        if(Boolean.TRUE.toString().equals(System.getProperty(ALLOW_DERIVATIONS_MATCHING_OTHER_SCRIPT_TYPES_PROPERTY))) {
            return false;
        }

        if(scriptType != null && scriptType.getAccount(derivationPath) > -1) {
            return false;
        }

        return Arrays.stream(ScriptType.values()).anyMatch(scriptType -> !scriptType.equals(this.scriptType) && scriptType.getAccount(derivationPath) > -1);
    }

    public boolean containsDuplicateKeystoreLabels() {
        if(keystores.size() <= 1) {
            return false;
        }

        return !keystores.stream().map(Keystore::getLabel).allMatch(new HashSet<>()::add);
    }

    public void makeLabelsUnique(Keystore newKeystore) {
        makeLabelsUnique(newKeystore, false);
    }

    private int makeLabelsUnique(Keystore newKeystore, boolean duplicateFound) {
        int max = 0;
        for(Keystore keystore : getKeystores()) {
            String newKeystoreLabel = newKeystore.getLabel().equals(Keystore.DEFAULT_LABEL) ? Keystore.DEFAULT_LABEL.substring(0, Keystore.DEFAULT_LABEL.length() - 2) : newKeystore.getLabel();
            if(newKeystore != keystore && keystore.getLabel().startsWith(newKeystoreLabel)) {
                duplicateFound = true;
                String remainder = keystore.getLabel().substring(newKeystoreLabel.length());
                if(remainder.length() == 0) {
                    max = makeLabelsUnique(keystore, true);
                } else {
                    try {
                        int count = Integer.parseInt(remainder.trim());
                        max = Math.max(max, count);
                    } catch (NumberFormatException e) {
                        //ignore, no terminating number
                    }
                }
            }
        }

        if(duplicateFound) {
            max++;
            if(newKeystore.getLabel().equals(Keystore.DEFAULT_LABEL)) {
                newKeystore.setLabel(Keystore.DEFAULT_LABEL.substring(0, Keystore.DEFAULT_LABEL.length() - 2) + " " + max);
            } else {
                newKeystore.setLabel(newKeystore.getLabel() + " " + max);
            }
        }

        return max;
    }

    public Wallet copy() {
        Wallet copy = new Wallet(name);
        copy.setPolicyType(policyType);
        copy.setScriptType(scriptType);
        copy.setDefaultPolicy(defaultPolicy.copy());
        for(Keystore keystore : keystores) {
            copy.getKeystores().add(keystore.copy());
        }
        for(WalletNode node : purposeNodes) {
            copy.purposeNodes.add(node.copy());
        }
        for(Sha256Hash hash : transactions.keySet()) {
            copy.transactions.put(hash, transactions.get(hash));
        }
        copy.setStoredBlockHeight(getStoredBlockHeight());
        copy.gapLimit = gapLimit;
        copy.birthDate = birthDate;

        return copy;
    }

    public boolean containsPrivateKeys() {
        for(Keystore keystore : keystores) {
            if(keystore.hasPrivateKey()) {
                return true;
            }
        }

        return false;
    }

    public boolean containsSource(KeystoreSource keystoreSource) {
        for(Keystore keystore : keystores) {
            if(keystoreSource.equals(keystore.getSource())) {
                return true;
            }
        }

        return false;
    }

    public boolean isEncrypted() {
        for(Keystore keystore : keystores) {
            if(keystore.isEncrypted()) {
                return true;
            }
        }

        return false;
    }

    public void encrypt(Key key) {
        for(Keystore keystore : keystores) {
            keystore.encrypt(key);
        }
    }

    public void decrypt(CharSequence password) {
        for(Keystore keystore : keystores) {
            keystore.decrypt(password);
        }
    }

    public void decrypt(Key key) {
        for(Keystore keystore : keystores) {
            keystore.decrypt(key);
        }
    }

    public void clearPrivate() {
        for(Keystore keystore : keystores) {
            keystore.clearPrivate();
        }
    }

    @Override
    public String toString() {
        return getName();
    }
}
