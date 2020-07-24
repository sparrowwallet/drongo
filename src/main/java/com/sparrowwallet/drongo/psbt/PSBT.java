package com.sparrowwallet.drongo.psbt;

import com.sparrowwallet.drongo.ExtendedKey;
import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.protocol.*;
import com.sparrowwallet.drongo.wallet.*;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.ByteBuffer;
import java.util.*;

import static com.sparrowwallet.drongo.psbt.PSBTEntry.*;

public class PSBT {
    public static final byte PSBT_GLOBAL_UNSIGNED_TX = 0x00;
    public static final byte PSBT_GLOBAL_BIP32_PUBKEY = 0x01;
    public static final byte PSBT_GLOBAL_VERSION = (byte)0xfb;
    public static final byte PSBT_GLOBAL_PROPRIETARY = (byte)0xfc;

    public static final String PSBT_MAGIC_HEX = "70736274";
    public static final int PSBT_MAGIC_INT = 1886610036;

    private static final int STATE_GLOBALS = 1;
    private static final int STATE_INPUTS = 2;
    private static final int STATE_OUTPUTS = 3;
    private static final int STATE_END = 4;

    private int inputs = 0;
    private int outputs = 0;

    private byte[] psbtBytes;

    private Transaction transaction = null;
    private Integer version = null;
    private final Map<ExtendedKey, KeyDerivation> extendedPublicKeys = new LinkedHashMap<>();
    private final Map<String, String> globalProprietary = new LinkedHashMap<>();

    private final List<PSBTInput> psbtInputs = new ArrayList<>();
    private final List<PSBTOutput> psbtOutputs = new ArrayList<>();

    private static final Logger log = LoggerFactory.getLogger(PSBT.class);

    public PSBT(Transaction transaction) {
        this.transaction = transaction;

        for(int i = 0; i < transaction.getInputs().size(); i++) {
            psbtInputs.add(new PSBTInput(transaction, i));
        }

        for(int i = 0; i < transaction.getOutputs().size(); i++) {
            psbtOutputs.add(new PSBTOutput());
        }
    }

    public PSBT(WalletTransaction walletTransaction) {
        Wallet wallet = walletTransaction.getWallet();

        transaction = new Transaction(walletTransaction.getTransaction().bitcoinSerialize());
        for(TransactionInput input : transaction.getInputs()) {
            input.clearScriptBytes();
            input.clearWitness();
        }
        for(Keystore keystore : walletTransaction.getWallet().getKeystores()) {
            extendedPublicKeys.put(keystore.getExtendedPublicKey(), keystore.getKeyDerivation());
        }
        version = 0;

        int inputIndex = 0;
        for(Iterator<Map.Entry<BlockTransactionHashIndex, WalletNode>> iter = walletTransaction.getSelectedUtxos().entrySet().iterator(); iter.hasNext(); inputIndex++) {
            Map.Entry<BlockTransactionHashIndex, WalletNode> utxoEntry = iter.next();
            Transaction utxo = wallet.getTransactions().get(utxoEntry.getKey().getHash()).getTransaction();
            int utxoIndex = (int)utxoEntry.getKey().getIndex();
            TransactionOutput utxoOutput = utxo.getOutputs().get(utxoIndex);

            TransactionInput txInput = walletTransaction.getTransaction().getInputs().get(inputIndex);

            Script redeemScript = null;
            if(ScriptType.P2SH.isScriptType(utxoOutput.getScript())) {
                redeemScript = txInput.getScriptSig().getFirstNestedScript();
            }

            Script witnessScript = null;
            if(txInput.getWitness() != null) {
                witnessScript = txInput.getWitness().getWitnessScript();
            }

            Map<ECKey, KeyDerivation> derivedPublicKeys = new LinkedHashMap<>();
            for(Keystore keystore : wallet.getKeystores()) {
                WalletNode walletNode = utxoEntry.getValue();
                derivedPublicKeys.put(keystore.getPubKey(walletNode), keystore.getKeyDerivation());
            }

            PSBTInput psbtInput = new PSBTInput(wallet.getScriptType(), transaction, inputIndex, utxo, utxoIndex, redeemScript, witnessScript, derivedPublicKeys, Collections.emptyMap());
            psbtInputs.add(psbtInput);
        }

        List<WalletNode> outputNodes = new ArrayList<>();
        outputNodes.add(wallet.getWalletAddresses().getOrDefault(walletTransaction.getRecipientAddress(), null));
        outputNodes.add(walletTransaction.getChangeNode());

        for(int outputIndex = 0; outputIndex < outputNodes.size(); outputIndex++) {
            WalletNode outputNode = outputNodes.get(outputIndex);
            if(outputNode == null) {
                PSBTOutput externalRecipientOutput = new PSBTOutput(null, null, Collections.emptyMap(), Collections.emptyMap());
                psbtOutputs.add(externalRecipientOutput);
            } else {
                TransactionOutput txOutput = walletTransaction.getTransaction().getOutputs().get(outputIndex);

                //Construct dummy transaction to spend the UTXO created by this wallet's txOutput
                Transaction transaction = new Transaction();
                TransactionInput spendingInput = wallet.addDummySpendingInput(transaction, outputNode, txOutput);

                Script redeemScript = null;
                if(ScriptType.P2SH.isScriptType(txOutput.getScript())) {
                    redeemScript = spendingInput.getScriptSig().getFirstNestedScript();
                }

                Script witnessScript = null;
                if(spendingInput.getWitness() != null) {
                    witnessScript = spendingInput.getWitness().getWitnessScript();
                }

                Map<ECKey, KeyDerivation> derivedPublicKeys = new LinkedHashMap<>();
                for(Keystore keystore : wallet.getKeystores()) {
                    derivedPublicKeys.put(keystore.getPubKey(outputNode), keystore.getKeyDerivation());
                }

                PSBTOutput walletOutput = new PSBTOutput(redeemScript, witnessScript, derivedPublicKeys, Collections.emptyMap());
                psbtOutputs.add(walletOutput);
            }
        }
    }

    public PSBT(byte[] psbt) throws PSBTParseException {
        this.psbtBytes = psbt;
        parse();
    }

    private void parse() throws PSBTParseException {
        int seenInputs = 0;
        int seenOutputs = 0;

        ByteBuffer psbtByteBuffer = ByteBuffer.wrap(psbtBytes);

        byte[] magicBuf = new byte[4];
        psbtByteBuffer.get(magicBuf);
        if (!PSBT_MAGIC_HEX.equalsIgnoreCase(Utils.bytesToHex(magicBuf))) {
            throw new PSBTParseException("PSBT has invalid magic value");
        }

        byte sep = psbtByteBuffer.get();
        if (sep != (byte) 0xff) {
            throw new PSBTParseException("PSBT has bad initial separator: " + Utils.bytesToHex(new byte[]{sep}));
        }

        int currentState = STATE_GLOBALS;
        List<PSBTEntry> globalEntries = new ArrayList<>();
        List<List<PSBTEntry>> inputEntryLists = new ArrayList<>();
        List<List<PSBTEntry>> outputEntryLists = new ArrayList<>();

        List<PSBTEntry> inputEntries = new ArrayList<>();
        List<PSBTEntry> outputEntries = new ArrayList<>();

        while (psbtByteBuffer.hasRemaining()) {
            PSBTEntry entry = new PSBTEntry(psbtByteBuffer);

            if(entry.getKey() == null) {         // length == 0
                switch (currentState) {
                    case STATE_GLOBALS:
                        currentState = STATE_INPUTS;
                        parseGlobalEntries(globalEntries);
                        break;
                    case STATE_INPUTS:
                        inputEntryLists.add(inputEntries);
                        inputEntries = new ArrayList<>();

                        seenInputs++;
                        if (seenInputs == inputs) {
                            currentState = STATE_OUTPUTS;
                            parseInputEntries(inputEntryLists);
                        }
                        break;
                    case STATE_OUTPUTS:
                        outputEntryLists.add(outputEntries);
                        outputEntries = new ArrayList<>();

                        seenOutputs++;
                        if (seenOutputs == outputs) {
                            currentState = STATE_END;
                            parseOutputEntries(outputEntryLists);
                        }
                        break;
                    case STATE_END:
                        break;
                    default:
                        throw new PSBTParseException("PSBT structure invalid");
                }
            } else if (currentState == STATE_GLOBALS) {
                globalEntries.add(entry);
            } else if (currentState == STATE_INPUTS) {
                inputEntries.add(entry);
            } else if (currentState == STATE_OUTPUTS) {
                outputEntries.add(entry);
            } else {
                throw new PSBTParseException("PSBT structure invalid");
            }
        }

        if(currentState != STATE_END) {
            if(transaction == null) {
                throw new PSBTParseException("Missing transaction");
            }

            if(currentState == STATE_INPUTS) {
                throw new PSBTParseException("Missing inputs");
            }

            if(currentState == STATE_OUTPUTS) {
                throw new PSBTParseException("Missing outputs");
            }
        }

        log.debug("Calculated fee at " + getFee());
    }

    private void parseGlobalEntries(List<PSBTEntry> globalEntries) throws PSBTParseException {
        PSBTEntry duplicate = findDuplicateKey(globalEntries);
        if(duplicate != null) {
            throw new PSBTParseException("Found duplicate key for PSBT global: " + Utils.bytesToHex(duplicate.getKey()));
        }

        for(PSBTEntry entry : globalEntries) {
            switch(entry.getKeyType()) {
                case PSBT_GLOBAL_UNSIGNED_TX:
                    entry.checkOneByteKey();
                    Transaction transaction = new Transaction(entry.getData());
                    transaction.verify();
                    inputs = transaction.getInputs().size();
                    outputs = transaction.getOutputs().size();
                    log.debug("Transaction with txid: " + transaction.getTxId() + " version " + transaction.getVersion() + " size " + transaction.getMessageSize() + " locktime " + transaction.getLocktime());
                    for(TransactionInput input: transaction.getInputs()) {
                        if(input.getScriptSig().getProgram().length != 0) {
                            throw new PSBTParseException("Unsigned tx input does not have empty scriptSig");
                        }
                        log.debug(" Transaction input references txid: " + input.getOutpoint().getHash() + " vout " + input.getOutpoint().getIndex() + " with script " + input.getScriptSig());
                    }
                    for(TransactionOutput output: transaction.getOutputs()) {
                        try {
                            log.debug(" Transaction output value: " + output.getValue() + " to addresses " + Arrays.asList(output.getScript().getToAddresses()) + " with script hex " + Utils.bytesToHex(output.getScript().getProgram()) + " to script " + output.getScript());
                        } catch(NonStandardScriptException e) {
                            log.debug(" Transaction output value: " + output.getValue() + " with script hex " + Utils.bytesToHex(output.getScript().getProgram()) + " to script " + output.getScript());
                        }
                    }
                    this.transaction = transaction;
                    break;
                case PSBT_GLOBAL_BIP32_PUBKEY:
                    entry.checkOneBytePlusXpubKey();
                    KeyDerivation keyDerivation = parseKeyDerivation(entry.getData());
                    ExtendedKey pubKey = ExtendedKey.fromDescriptor(Base58.encodeChecked(entry.getKeyData()));
                    this.extendedPublicKeys.put(pubKey, keyDerivation);
                    log.debug("Pubkey with master fingerprint " + keyDerivation.getMasterFingerprint() + " at path " + keyDerivation.getDerivationPath() + ": " + pubKey.getExtendedKey());
                    break;
                case PSBT_GLOBAL_VERSION:
                    entry.checkOneByteKey();
                    int version = (int)Utils.readUint32(entry.getData(), 0);
                    this.version = version;
                    log.debug("PSBT version: " + version);
                    break;
                case PSBT_GLOBAL_PROPRIETARY:
                    globalProprietary.put(Utils.bytesToHex(entry.getKeyData()), Utils.bytesToHex(entry.getData()));
                    log.debug("PSBT global proprietary data: " + Utils.bytesToHex(entry.getData()));
                    break;
                default:
                    log.warn("PSBT global not recognized key type: " + entry.getKeyType());
            }
        }
    }

    private void parseInputEntries(List<List<PSBTEntry>> inputEntryLists) throws PSBTParseException {
        for(List<PSBTEntry> inputEntries : inputEntryLists) {
            PSBTEntry duplicate = findDuplicateKey(inputEntries);
            if(duplicate != null) {
                throw new PSBTParseException("Found duplicate key for PSBT input: " + Utils.bytesToHex(duplicate.getKey()));
            }

            int inputIndex = this.psbtInputs.size();
            PSBTInput input = new PSBTInput(inputEntries, transaction, inputIndex);

            boolean verified = input.verifySignatures();
            if(!verified && input.getPartialSignatures().size() > 0) {
                throw new PSBTParseException("Unverifiable partial signatures provided");
            }

            this.psbtInputs.add(input);
        }
    }

    private void parseOutputEntries(List<List<PSBTEntry>> outputEntryLists) throws PSBTParseException {
        for(List<PSBTEntry> outputEntries : outputEntryLists) {
            PSBTEntry duplicate = findDuplicateKey(outputEntries);
            if(duplicate != null) {
                throw new PSBTParseException("Found duplicate key for PSBT output: " + Utils.bytesToHex(duplicate.getKey()));
            }

            PSBTOutput output = new PSBTOutput(outputEntries);
            this.psbtOutputs.add(output);
        }
    }

    private PSBTEntry findDuplicateKey(List<PSBTEntry> entries) {
        Set<String> checkSet = new HashSet<>();
        for(PSBTEntry entry: entries) {
            if(!checkSet.add(Utils.bytesToHex(entry.getKey())) ) {
                return entry;
            }
        }

        return null;
    }

    public Long getFee() {
        long fee = 0L;

        for(PSBTInput input : psbtInputs) {
            TransactionOutput utxo = input.getUtxo();

            if(utxo != null) {
                fee += utxo.getValue();
            } else {
                log.error("Cannot determine fee - not enough information provided on inputs");
                return null;
            }
        }

        for (int i = 0; i < transaction.getOutputs().size(); i++) {
            TransactionOutput output = transaction.getOutputs().get(i);
            fee -= output.getValue();
        }

        return fee;
    }

    public boolean hasSignatures() {
        for(PSBTInput psbtInput : getPsbtInputs()) {
            if(!psbtInput.getPartialSignatures().isEmpty() || psbtInput.getFinalScriptSig() != null || psbtInput.getFinalScriptWitness() != null) {
                return true;
            }
        }

        return false;
    }

    public boolean isSigned() {
        for(PSBTInput psbtInput : getPsbtInputs()) {
            if(!psbtInput.isSigned()) {
                return false;
            }
        }

        return true;
    }

    private List<PSBTEntry> getGlobalEntries() {
        List<PSBTEntry> entries = new ArrayList<>();

        if(transaction != null) {
            entries.add(populateEntry(PSBT_GLOBAL_UNSIGNED_TX, null, transaction.bitcoinSerialize()));
        }

        for(Map.Entry<ExtendedKey, KeyDerivation> entry : extendedPublicKeys.entrySet()) {
            entries.add(populateEntry(PSBT_GLOBAL_BIP32_PUBKEY, entry.getKey().getExtendedKeyBytes(), serializeKeyDerivation(entry.getValue())));
        }

        if(version != null) {
            byte[] versionBytes = new byte[4];
            Utils.uint32ToByteArrayLE(version, versionBytes, 0);
            entries.add(populateEntry(PSBT_GLOBAL_VERSION, null, versionBytes));
        }

        for(Map.Entry<String, String> entry : globalProprietary.entrySet()) {
            entries.add(populateEntry(PSBT_GLOBAL_PROPRIETARY, Utils.hexToBytes(entry.getKey()), Utils.hexToBytes(entry.getValue())));
        }

        return entries;
    }

    public byte[] serialize() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        baos.writeBytes(Utils.hexToBytes(PSBT_MAGIC_HEX));
        baos.writeBytes(new byte[] {(byte)0xff});

        List<PSBTEntry> globalEntries = getGlobalEntries();
        for(PSBTEntry entry : globalEntries) {
            entry.serializeToStream(baos);
        }
        baos.writeBytes(new byte[] {(byte)0x00});

        for(PSBTInput psbtInput : getPsbtInputs()) {
            List<PSBTEntry> inputEntries = psbtInput.getInputEntries();
            for(PSBTEntry entry : inputEntries) {
                entry.serializeToStream(baos);
            }
            baos.writeBytes(new byte[] {(byte)0x00});
        }

        for(PSBTOutput psbtOutput : getPsbtOutputs()) {
            List<PSBTEntry> outputEntries = psbtOutput.getOutputEntries();
            for(PSBTEntry entry : outputEntries) {
                entry.serializeToStream(baos);
            }
            baos.writeBytes(new byte[] {(byte)0x00});
        }

        return baos.toByteArray();
    }

    public void combine(PSBT... psbts) {
        for(PSBT psbt : psbts) {
            combine(psbt);
        }
    }

    public void combine(PSBT psbt) {
        byte[] txBytes = transaction.bitcoinSerialize();
        byte[] psbtTxBytes = psbt.getTransaction().bitcoinSerialize();

        if(!Arrays.equals(txBytes, psbtTxBytes)) {
            throw new IllegalArgumentException("Provided PSBT does contain a matching global transaction");
        }

        for(PSBTInput psbtInput : psbt.getPsbtInputs()) {
            if(psbtInput.getFinalScriptSig() != null || psbtInput.getFinalScriptWitness() != null) {
                throw new IllegalArgumentException("Cannot combine an already finalised PSBT");
            }
        }

        if(psbt.getVersion() != null) {
            version = psbt.getVersion();
        }

        extendedPublicKeys.putAll(psbt.extendedPublicKeys);
        globalProprietary.putAll(psbt.globalProprietary);

        for(int i = 0; i < getPsbtInputs().size(); i++) {
            PSBTInput thisInput = getPsbtInputs().get(i);
            PSBTInput otherInput = psbt.getPsbtInputs().get(i);
            thisInput.combine(otherInput);
        }

        for(int i = 0; i < getPsbtOutputs().size(); i++) {
            PSBTOutput thisOutput = getPsbtOutputs().get(i);
            PSBTOutput otherOutput = psbt.getPsbtOutputs().get(i);
            thisOutput.combine(otherOutput);
        }
    }

    public Transaction extractTransaction() {
        boolean hasWitness = false;
        for(PSBTInput psbtInput : getPsbtInputs()) {
            if(psbtInput.getFinalScriptSig() == null) {
                return null;
            }
            if(psbtInput.getFinalScriptWitness() != null) {
                hasWitness = true;
            }
        }

        if(hasWitness && !transaction.isSegwit()) {
            transaction.setSegwitVersion(1);
        }

        for(int i = 0; i < transaction.getInputs().size(); i++) {
            TransactionInput txInput = transaction.getInputs().get(i);
            PSBTInput psbtInput = getPsbtInputs().get(i);
            txInput.setScriptBytes(psbtInput.getFinalScriptSig().getProgram());

            if(hasWitness) {
                if(psbtInput.getFinalScriptWitness() != null) {
                    txInput.setWitness(psbtInput.getFinalScriptWitness());
                } else {
                    txInput.setWitness(new TransactionWitness(transaction));
                }
            }
        }

        return transaction;
    }

    public List<PSBTInput> getPsbtInputs() {
        return psbtInputs;
    }

    public List<PSBTOutput> getPsbtOutputs() {
        return psbtOutputs;
    }

    public Transaction getTransaction() {
        return transaction;
    }

    public Integer getVersion() {
        return version;
    }

    public KeyDerivation getKeyDerivation(ExtendedKey publicKey) {
        return extendedPublicKeys.get(publicKey);
    }

    public List<ExtendedKey> getExtendedPublicKeys() {
        return new ArrayList<ExtendedKey>(extendedPublicKeys.keySet());
    }

    public Map<String, String> getGlobalProprietary() {
        return globalProprietary;
    }

    public String toString() {
        return Utils.bytesToHex(serialize());
    }

    public String toBase64String() {
        return Base64.toBase64String(serialize());
    }

    public static boolean isPSBT(byte[] b) {
        try {
            ByteBuffer buffer = ByteBuffer.wrap(b);
            int header = buffer.getInt();
            return header == PSBT_MAGIC_INT;
        } catch (Exception e) {
            //ignore
        }

        return false;
    }

    public static boolean isPSBT(String s) {
        if (Utils.isHex(s) && s.startsWith(PSBT_MAGIC_HEX)) {
            return true;
        } else {
            return Utils.isBase64(s) && Utils.bytesToHex(Base64.decode(s)).startsWith(PSBT_MAGIC_HEX);
        }
    }

    public static PSBT fromString(String strPSBT) throws PSBTParseException {
        if (!isPSBT(strPSBT)) {
            throw new PSBTParseException("Provided string is not a PSBT");
        }

        if (Utils.isBase64(strPSBT) && !Utils.isHex(strPSBT)) {
            strPSBT = Utils.bytesToHex(Base64.decode(strPSBT));
        }

        byte[] psbtBytes = Utils.hexToBytes(strPSBT);
        return new PSBT(psbtBytes);
    }
}
