package com.sparrowwallet.drongo.psbt;

import com.sparrowwallet.drongo.ExtendedKey;
import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.address.Address;
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
import static com.sparrowwallet.drongo.psbt.PSBTInput.*;
import static com.sparrowwallet.drongo.psbt.PSBTOutput.*;
import static com.sparrowwallet.drongo.wallet.Wallet.addDummySpendingInput;

public class PSBT {
    public static final byte PSBT_GLOBAL_UNSIGNED_TX = 0x00;
    public static final byte PSBT_GLOBAL_BIP32_PUBKEY = 0x01;
    public static final byte PSBT_GLOBAL_TX_VERSION = 0x02;
    public static final byte PSBT_GLOBAL_FALLBACK_LOCKTIME = 0x03;
    public static final byte PSBT_GLOBAL_INPUT_COUNT = 0x04;
    public static final byte PSBT_GLOBAL_OUTPUT_COUNT = 0x05;
    public static final byte PSBT_GLOBAL_TX_MODIFIABLE = 0x06;
    public static final byte PSBT_GLOBAL_VERSION = (byte)0xfb;
    public static final byte PSBT_GLOBAL_PROPRIETARY = (byte)0xfc;

    public static final String PSBT_MAGIC_HEX = "70736274";
    public static final int PSBT_MAGIC_INT = 1886610036;

    public static final int STATE_GLOBALS = 1;
    public static final int STATE_INPUTS = 2;
    public static final int STATE_OUTPUTS = 3;
    public static final int STATE_END = 4;

    private int inputs = 0;
    private int outputs = 0;

    private byte[] psbtBytes;

    private Transaction transaction = null;
    private Integer version = null;
    private final Map<ExtendedKey, KeyDerivation> extendedPublicKeys = new LinkedHashMap<>();
    private final Map<String, String> globalProprietary = new LinkedHashMap<>();

    //PSBTv2 fields
    private Long txVersion = null;
    private Long fallbackLocktime = null;
    private Long inputCount = null;
    private Long outputCount = null;
    private Byte modifiable = null;

    private final List<PSBTInput> psbtInputs = new ArrayList<>();
    private final List<PSBTOutput> psbtOutputs = new ArrayList<>();

    private static final Logger log = LoggerFactory.getLogger(PSBT.class);

    public PSBT(Transaction transaction) {
        this.transaction = transaction;

        for(int i = 0; i < transaction.getInputs().size(); i++) {
            psbtInputs.add(new PSBTInput(this, i));
        }

        for(int i = 0; i < transaction.getOutputs().size(); i++) {
            psbtOutputs.add(new PSBTOutput(this, i));
        }
    }

    public PSBT(WalletTransaction walletTransaction) {
        this(walletTransaction, null, true);
    }

    public PSBT(WalletTransaction walletTransaction, Integer version, boolean includeGlobalXpubs) {
        Wallet wallet = walletTransaction.getWallet();

        transaction = new Transaction(walletTransaction.getTransaction().bitcoinSerialize());

        //Clear segwit marker & flag, scriptSigs and all witness data as per BIP174
        transaction.clearSegwit();
        for(TransactionInput input : transaction.getInputs()) {
            input.clearScriptBytes();
            input.setWitness(null);
        }

        //Shuffle outputs so change outputs are less obvious
        transaction.shuffleOutputs();

        if(includeGlobalXpubs) {
            for(Keystore keystore : walletTransaction.getWallet().getKeystores()) {
                extendedPublicKeys.put(keystore.getExtendedPublicKey(), keystore.getKeyDerivation());
            }
        }

        if(version != null) {
            this.version = version;
        }

        int inputIndex = 0;
        for(Iterator<Map.Entry<BlockTransactionHashIndex, WalletNode>> iter = walletTransaction.getSelectedUtxos().entrySet().iterator(); iter.hasNext(); inputIndex++) {
            Map.Entry<BlockTransactionHashIndex, WalletNode> utxoEntry = iter.next();

            WalletNode walletNode = utxoEntry.getValue();
            Wallet signingWallet = walletNode.getWallet();

            boolean alwaysIncludeNonWitnessTx = signingWallet.getKeystores().stream().anyMatch(keystore -> keystore.getWalletModel().alwaysIncludeNonWitnessUtxo())
                    && !ScriptType.P2TR.equals(signingWallet.getScriptType());

            Transaction utxo = signingWallet.getTransactions().get(utxoEntry.getKey().getHash()).getTransaction();
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
            ECKey tapInternalKey = null;
            for(Keystore keystore : signingWallet.getKeystores()) {
                derivedPublicKeys.put(signingWallet.getScriptType().getOutputKey(keystore.getPubKey(walletNode)), keystore.getKeyDerivation().extend(walletNode.getDerivation()));

                //TODO: Implement Musig for multisig wallets
                if(signingWallet.getScriptType() == ScriptType.P2TR) {
                    tapInternalKey = keystore.getPubKey(walletNode);
                }
            }

            PSBTInput psbtInput = new PSBTInput(this, signingWallet.getScriptType(), inputIndex, utxo, utxoIndex, redeemScript, witnessScript, derivedPublicKeys, Collections.emptyMap(), tapInternalKey, alwaysIncludeNonWitnessTx);
            psbtInputs.add(psbtInput);
        }

        List<WalletNode> outputNodes = new ArrayList<>();
        for(TransactionOutput txOutput : transaction.getOutputs()) {
            try {
                Address address = txOutput.getScript().getToAddresses()[0];
                if(walletTransaction.getAddressNodeMap().containsKey(address)) {
                    outputNodes.add(walletTransaction.getAddressNodeMap().get(address));
                } else if(walletTransaction.getChangeMap().keySet().stream().anyMatch(changeNode -> changeNode.getAddress().equals(address))) {
                    outputNodes.add(walletTransaction.getChangeMap().keySet().stream().filter(changeNode -> changeNode.getAddress().equals(address)).findFirst().orElse(null));
                }
            } catch(NonStandardScriptException e) {
                //Ignore, likely OP_RETURN output
                outputNodes.add(null);
            }
        }

        for(int outputIndex = 0; outputIndex < outputNodes.size(); outputIndex++) {
            WalletNode outputNode = outputNodes.get(outputIndex);
            if(outputNode == null) {
                PSBTOutput externalRecipientOutput = new PSBTOutput(this, outputIndex, null, null, null, Collections.emptyMap(), Collections.emptyMap(), null);
                psbtOutputs.add(externalRecipientOutput);
            } else {
                TransactionOutput txOutput = transaction.getOutputs().get(outputIndex);
                Wallet recipientWallet = outputNode.getWallet();

                //Construct dummy transaction to spend the UTXO created by this wallet's txOutput
                Transaction transaction = new Transaction();
                TransactionInput spendingInput = addDummySpendingInput(transaction, outputNode, txOutput);

                Script redeemScript = null;
                if(ScriptType.P2SH.isScriptType(txOutput.getScript())) {
                    redeemScript = spendingInput.getScriptSig().getFirstNestedScript();
                }

                Script witnessScript = null;
                if(spendingInput.getWitness() != null) {
                    witnessScript = spendingInput.getWitness().getWitnessScript();
                }

                Map<ECKey, KeyDerivation> derivedPublicKeys = new LinkedHashMap<>();
                ECKey tapInternalKey = null;
                for(Keystore keystore : recipientWallet.getKeystores()) {
                    derivedPublicKeys.put(recipientWallet.getScriptType().getOutputKey(keystore.getPubKey(outputNode)), keystore.getKeyDerivation().extend(outputNode.getDerivation()));

                    //TODO: Implement Musig for multisig wallets
                    if(recipientWallet.getScriptType() == ScriptType.P2TR) {
                        tapInternalKey = keystore.getPubKey(outputNode);
                    }
                }

                PSBTOutput walletOutput = new PSBTOutput(this, outputIndex, recipientWallet.getScriptType(), redeemScript, witnessScript, derivedPublicKeys, Collections.emptyMap(), tapInternalKey);
                psbtOutputs.add(walletOutput);
            }
        }
    }

    public PSBT(byte[] psbt) throws PSBTParseException {
        this(psbt, true);
    }

    public PSBT(byte[] psbt, boolean verifySignatures) throws PSBTParseException {
        this.psbtBytes = psbt;
        parse(verifySignatures);
    }

    private void parse(boolean verifySignatures) throws PSBTParseException {
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
            if(getPsbtVersion() == 0 && transaction == null) {
                throw new PSBTParseException("Missing transaction");
            }
        }

        if(verifySignatures) {
            verifySignatures(psbtInputs);
        }

        if(log.isDebugEnabled()) {
            log.debug("Calculated fee at " + getFee());
        }
    }

    private void parseGlobalEntries(List<PSBTEntry> globalEntries) throws PSBTParseException {
        PSBTEntry duplicate = findDuplicateKey(globalEntries);
        if(duplicate != null) {
            throw new PSBTParseException("Found duplicate key for PSBT global: " + Utils.bytesToHex(duplicate.getKey()));
        }

        for(PSBTEntry entry : globalEntries) {
            switch((byte)entry.getKeyType()) {
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
                case PSBT_GLOBAL_TX_VERSION:
                    entry.checkOneByteKey();
                    long txVersion = Utils.readUint32(entry.getData(), 0);
                    this.txVersion = txVersion;
                    log.debug("PSBT tx version: " + txVersion);
                    break;
                case PSBT_GLOBAL_FALLBACK_LOCKTIME:
                    entry.checkOneByteKey();
                    long fallbackLocktime = Utils.readUint32(entry.getData(), 0);
                    this.fallbackLocktime = fallbackLocktime;
                    log.debug("PSBT fallback locktime: " + fallbackLocktime);
                    break;
                case PSBT_GLOBAL_INPUT_COUNT:
                    entry.checkOneByteKey();
                    VarInt varIntInputCount = new VarInt(entry.getData(), 0);
                    this.inputCount = varIntInputCount.value;
                    this.inputs = inputCount.intValue();
                    log.debug("PSBT input count: " + inputCount);
                    break;
                case PSBT_GLOBAL_OUTPUT_COUNT:
                    entry.checkOneByteKey();
                    VarInt varIntOutputCount = new VarInt(entry.getData(), 0);
                    this.outputCount = varIntOutputCount.value;
                    this.outputs = outputCount.intValue();
                    log.debug("PSBT output count: " + outputCount);
                    break;
                case PSBT_GLOBAL_TX_MODIFIABLE:
                    entry.checkOneByteKey();
                    if(entry.getData().length != 1) {
                        throw new PSBTParseException("Tx modifiable field was not a single byte");
                    }
                    this.modifiable = entry.getData()[0];
                    log.debug("PSBT tx modifiable: " + String.format("%8s", Integer.toBinaryString(modifiable & 0xFF)).replace(' ', '0'));
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

        if(getPsbtVersion() == 0) {
            if(transaction == null) {
                throw new PSBTParseException("PSBT_GLOBAL_UNSIGNED_TX is required in PSBTv0");
            }
            if(txVersion != null) {
                throw new PSBTParseException("PSBT_GLOBAL_TX_VERSION is not allowed in PSBTv0");
            }
            if(fallbackLocktime != null) {
                throw new PSBTParseException("PSBT_GLOBAL_FALLBACK_LOCKTIME is not allowed in PSBTv0");
            }
            if(inputCount != null) {
                throw new PSBTParseException("PSBT_GLOBAL_INPUT_COUNT is not allowed in PSBTv0");
            }
            if(outputCount != null) {
                throw new PSBTParseException("PSBT_GLOBAL_OUTPUT_COUNT is not allowed in PSBTv0");
            }
            if(modifiable != null) {
                throw new PSBTParseException("PSBT_GLOBAL_TX_MODIFIABLE is not allowed in PSBTv0");
            }
        } else if(getPsbtVersion() == 1) {
            throw new PSBTParseException("There is no PSBTv1");
        } else if(getPsbtVersion() >= 2) {
            if(transaction != null) {
                throw new PSBTParseException("PSBT_GLOBAL_UNSIGNED_TX is not allowed in PSBTv2");
            }
            if(txVersion == null) {
                throw new PSBTParseException("PSBT_GLOBAL_TX_VERSION is required in PSBTv2");
            }
            if(inputCount == null) {
                throw new PSBTParseException("PSBT_GLOBAL_INPUT_COUNT is required in PSBTv2");
            }
            if(outputCount == null) {
                throw new PSBTParseException("PSBT_GLOBAL_OUTPUT_COUNT is required in PSBTv2");
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
            PSBTInput input = new PSBTInput(this, inputEntries, inputIndex);

            if(getPsbtVersion() == 0) {
                if(input.prevTxid() != null) {
                    throw new PSBTParseException("PSBT_IN_PREV_TXID is not allowed in PSBTv0");
                }
                if(input.prevIndex() != null) {
                    throw new PSBTParseException("PSBT_IN_OUTPUT_INDEX is not allowed in PSBTv0");
                }
                if(input.sequence() != null) {
                    throw new PSBTParseException("PSBT_IN_SEQUENCE is not allowed in PSBTv0");
                }
                if(input.getRequiredTimeLocktime() != null) {
                    throw new PSBTParseException("PSBT_IN_REQUIRED_TIME_LOCKTIME is not allowed in PSBTv0");
                }
                if(input.getRequiredHeightLocktime() != null) {
                    throw new PSBTParseException("PSBT_IN_REQUIRED_HEIGHT_LOCKTIME is not allowed in PSBTv0");
                }
            } else if(getPsbtVersion() >= 2) {
                if(input.prevTxid() == null) {
                    throw new PSBTParseException("PSBT_IN_PREV_TXID is required in PSBTv2");
                }
                if(input.prevIndex() == null) {
                    throw new PSBTParseException("PSBT_IN_OUTPUT_INDEX is required in PSBTv2");
                }
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

            int outputIndex = this.psbtOutputs.size();
            PSBTOutput output = new PSBTOutput(this, outputEntries, outputIndex);

            if(getPsbtVersion() == 0) {
                if(output.amount() != null) {
                    throw new PSBTParseException("PSBT_OUT_AMOUNT is not allowed in PSBTv0");
                }
                if(output.script() != null) {
                    throw new PSBTParseException("PSBT_OUT_SCRIPT is not allowed in PSBTv0");
                }
            } else if(getPsbtVersion() >= 2) {
                if(output.amount() == null) {
                    throw new PSBTParseException("PSBT_OUT_AMOUNT is required in PSBTv2");
                }
                if(output.script() == null) {
                    throw new PSBTParseException("PSBT_OUT_SCRIPT is required in PSBTv2");
                }
            }

            this.psbtOutputs.add(output);
        }
    }

    int getPsbtVersion() {
        return version == null ? 0 : version;
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
                log.warn("Cannot determine fee - inputs are missing UTXO data");
                return null;
            }
        }

        for(PSBTOutput output : psbtOutputs) {
            fee -= output.getAmount();
        }

        return fee;
    }

    public void verifySignatures() throws PSBTSignatureException {
        verifySignatures(getPsbtInputs());
    }

    private void verifySignatures(List<PSBTInput> psbtInputs) throws PSBTSignatureException {
        for(PSBTInput input : psbtInputs) {
            boolean verified = input.verifySignatures();
            if(!verified && !input.getPartialSignatures().isEmpty()) {
                throw new PSBTSignatureException("Unverifiable partial signatures provided");
            }
            if(!verified && input.isTaproot() && input.getTapKeyPathSignature() != null) {
                throw new PSBTSignatureException("Unverifiable taproot keypath signature provided");
            }
        }
    }

    public boolean hasSignatures() {
        for(PSBTInput psbtInput : getPsbtInputs()) {
            if(!psbtInput.getPartialSignatures().isEmpty() || psbtInput.getTapKeyPathSignature() != null || psbtInput.getFinalScriptSig() != null || psbtInput.getFinalScriptWitness() != null) {
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

    public boolean isFinalized() {
        for(PSBTInput psbtInput : getPsbtInputs()) {
            if(!psbtInput.isFinalized()) {
                return false;
            }
        }

        return true;
    }

    private List<PSBTEntry> getGlobalEntries() {
        List<PSBTEntry> entries = new ArrayList<>();

        if(getPsbtVersion() == 0 && transaction != null) {
            entries.add(populateEntry(PSBT_GLOBAL_UNSIGNED_TX, null, transaction.bitcoinSerialize(false)));
        }

        for(Map.Entry<ExtendedKey, KeyDerivation> entry : extendedPublicKeys.entrySet()) {
            entries.add(populateEntry(PSBT_GLOBAL_BIP32_PUBKEY, entry.getKey().getExtendedKeyBytes(), serializeKeyDerivation(entry.getValue())));
        }

        if(getPsbtVersion() >= 2) {
            if(txVersion != null) {
                byte[] txVersionBytes = new byte[4];
                Utils.uint32ToByteArrayLE(txVersion, txVersionBytes, 0);
                entries.add(populateEntry(PSBT_GLOBAL_TX_VERSION, null, txVersionBytes));
            }
            if(fallbackLocktime != null) {
                byte[] fallbackLocktimeBytes = new byte[4];
                Utils.uint32ToByteArrayLE(fallbackLocktime, fallbackLocktimeBytes, 0);
                entries.add(populateEntry(PSBT_GLOBAL_FALLBACK_LOCKTIME, null, fallbackLocktimeBytes));
            }
            if(inputCount != null) {
                VarInt varIntInputCount = new VarInt(inputCount);
                entries.add(populateEntry(PSBT_GLOBAL_INPUT_COUNT, null, varIntInputCount.encode()));
            }
            if(outputCount != null) {
                VarInt varIntOutputCount = new VarInt(outputCount);
                entries.add(populateEntry(PSBT_GLOBAL_OUTPUT_COUNT, null, varIntOutputCount.encode()));
            }
            if(modifiable != null) {
                entries.add(populateEntry(PSBT_GLOBAL_TX_MODIFIABLE, null, new byte[] { modifiable }));
            }
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
        return serialize(true, true);
    }

    public byte[] serialize(boolean includeXpubs, boolean includeNonWitnessUtxos) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        baos.writeBytes(Utils.hexToBytes(PSBT_MAGIC_HEX));
        baos.writeBytes(new byte[] {(byte)0xff});

        List<PSBTEntry> globalEntries = getGlobalEntries();
        for(PSBTEntry entry : globalEntries) {
            if(includeXpubs || (entry.getKeyType() != PSBT_GLOBAL_BIP32_PUBKEY && entry.getKeyType() != PSBT_GLOBAL_PROPRIETARY)) {
                entry.serializeToStream(baos);
            }
        }
        baos.writeBytes(new byte[] {(byte)0x00});

        for(PSBTInput psbtInput : getPsbtInputs()) {
            List<PSBTEntry> inputEntries = psbtInput.getInputEntries(getPsbtVersion());
            for(PSBTEntry entry : inputEntries) {
                if((includeXpubs || (entry.getKeyType() != PSBT_IN_BIP32_DERIVATION && entry.getKeyType() != PSBT_IN_PROPRIETARY
                        && entry.getKeyType() != PSBT_IN_TAP_INTERNAL_KEY && entry.getKeyType() != PSBT_IN_TAP_BIP32_DERIVATION))
                        && (includeNonWitnessUtxos || entry.getKeyType() != PSBT_IN_NON_WITNESS_UTXO)) {
                    entry.serializeToStream(baos);
                }
            }
            baos.writeBytes(new byte[] {(byte)0x00});
        }

        for(PSBTOutput psbtOutput : getPsbtOutputs()) {
            List<PSBTEntry> outputEntries = psbtOutput.getOutputEntries(getPsbtVersion());
            for(PSBTEntry entry : outputEntries) {
                if(includeXpubs || (entry.getKeyType() != PSBT_OUT_REDEEM_SCRIPT && entry.getKeyType() != PSBT_OUT_WITNESS_SCRIPT
                        && entry.getKeyType() != PSBT_OUT_BIP32_DERIVATION && entry.getKeyType() != PSBT_OUT_PROPRIETARY
                        && entry.getKeyType() != PSBT_OUT_TAP_INTERNAL_KEY && entry.getKeyType() != PSBT_OUT_TAP_BIP32_DERIVATION)) {
                    entry.serializeToStream(baos);
                }
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
        if(getPsbtVersion() != psbt.getPsbtVersion()) {
            psbt.convertVersion(getPsbtVersion());
        }

        byte[] txBytes = getTransaction().bitcoinSerialize();
        byte[] psbtTxBytes = psbt.getTransaction().bitcoinSerialize();

        if(!Arrays.equals(txBytes, psbtTxBytes)) {
            throw new IllegalArgumentException("Provided PSBT does contain a matching global transaction");
        }

        if(isFinalized() || psbt.isFinalized()) {
            throw new IllegalArgumentException("Cannot combine an already finalised PSBT");
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
            if(psbtInput.getFinalScriptWitness() != null) {
                hasWitness = true;
            }
        }

        Transaction finalTransaction = new Transaction(getTransaction().bitcoinSerialize());

        if(hasWitness && !finalTransaction.isSegwit()) {
            finalTransaction.setSegwitFlag(Transaction.DEFAULT_SEGWIT_FLAG);
        }

        for(int i = 0; i < finalTransaction.getInputs().size(); i++) {
            TransactionInput txInput = finalTransaction.getInputs().get(i);
            PSBTInput psbtInput = getPsbtInputs().get(i);
            txInput.setScriptBytes(psbtInput.getFinalScriptSig() == null ? new byte[0] : psbtInput.getFinalScriptSig().getProgram());

            if(hasWitness) {
                if(psbtInput.getFinalScriptWitness() != null) {
                    txInput.setWitness(psbtInput.getFinalScriptWitness());
                } else {
                    txInput.setWitness(new TransactionWitness(finalTransaction));
                }
            }
        }

        return finalTransaction;
    }

    public PSBT getPublicCopy() {
        try {
            PSBT publicCopy = new PSBT(serialize());
            publicCopy.extendedPublicKeys.clear();
            publicCopy.globalProprietary.clear();
            for(PSBTInput psbtInput : publicCopy.getPsbtInputs()) {
                psbtInput.getDerivedPublicKeys().clear();
                psbtInput.getProprietary().clear();
            }
            for(PSBTOutput psbtOutput : publicCopy.getPsbtOutputs()) {
                psbtOutput.getDerivedPublicKeys().clear();
                psbtOutput.getProprietary().clear();
            }

            return publicCopy;
        } catch(PSBTParseException e) {
            throw new IllegalStateException("Could not parse PSBT", e);
        }
    }

    public void moveInput(int fromIndex, int toIndex) {
        moveItem(psbtInputs, fromIndex, toIndex);
        getTransaction().moveInput(fromIndex, toIndex);
        for(int i = 0; i < psbtInputs.size(); i++) {
            psbtInputs.get(i).setIndex(i);
        }
    }

    public void moveOutput(int fromIndex, int toIndex) {
        moveItem(psbtOutputs, fromIndex, toIndex);
        getTransaction().moveOutput(fromIndex, toIndex);
        for(int i = 0; i < psbtOutputs.size(); i++) {
            psbtOutputs.get(i).setIndex(i);
        }
    }

    private <T> void moveItem(List<T> list, int fromIndex, int toIndex) {
        if(fromIndex < 0 || fromIndex >= list.size() || toIndex < 0 || toIndex >= list.size()) {
            throw new IllegalArgumentException("Invalid indices [" + fromIndex + ", " + toIndex + "] provided to list of size " + list.size());
        }

        T item = list.remove(fromIndex);
        list.add(toIndex, item);
    }

    public List<PSBTInput> getPsbtInputs() {
        return psbtInputs;
    }

    public List<PSBTOutput> getPsbtOutputs() {
        return psbtOutputs;
    }

    public Transaction getTransaction() {
        return getTransaction(true);
    }

    public Transaction getTransaction(boolean setSequence) {
        if(getPsbtVersion() >= 2) {
            Transaction transaction = new Transaction();
            transaction.setVersion(txVersion);
            transaction.setLocktime(getLocktime(psbtInputs, fallbackLocktime));
            for(PSBTInput psbtInput : getPsbtInputs()) {
                TransactionInput transactionInput = transaction.addInput(psbtInput.getPrevTxid(), psbtInput.getPrevIndex(), new Script(new byte[0]));
                if(setSequence) {
                    if(psbtInput.getSequence() == null) {
                        transactionInput.setSequenceNumber(TransactionInput.SEQUENCE_LOCKTIME_DISABLED);
                    } else {
                        transactionInput.setSequenceNumber(psbtInput.getSequence());
                    }
                } else {
                    //Sequence number is set to zero to provide a static txid while updating
                    transactionInput.setSequenceNumber(0);
                }
            }
            for(PSBTOutput psbtOutput : getPsbtOutputs()) {
                transaction.addOutput(psbtOutput.getAmount(), psbtOutput.getScript());
            }
            return transaction;
        }

        return transaction;
    }

    public Integer getVersion() {
        return version;
    }

    public KeyDerivation getKeyDerivation(ExtendedKey publicKey) {
        return extendedPublicKeys.get(publicKey);
    }

    public Map<ExtendedKey, KeyDerivation> getExtendedPublicKeys() {
        return extendedPublicKeys;
    }

    public Long getTxVersion() {
        if(getPsbtVersion() >= 2) {
            return txVersion;
        }

        return getTransaction().getVersion();
    }

    public Long getFallbackLocktime() {
        if(getPsbtVersion() >= 2) {
            return fallbackLocktime;
        }

        return getTransaction().getLocktime();
    }

    public Long getInputCount() {
        if(getPsbtVersion() >= 2) {
            return inputCount;
        }

        return (long)getTransaction().getInputs().size();
    }

    public Long getOutputCount() {
        if(getPsbtVersion() >= 2) {
            return outputCount;
        }

        return (long)getTransaction().getOutputs().size();
    }

    public Byte getModifiable() {
        return modifiable;
    }

    public Boolean isInputsModifiable() {
        return modifiable == null ? null : (modifiable & (byte)0x01) > 0;
    }

    public void setInputsModifiable(boolean inputsModifiable) {
        if(modifiable != null) {
            modifiable = inputsModifiable ? (byte)(modifiable | (byte)0x01) : (byte)(modifiable & (byte)0xFE);
        }
    }

    public Boolean isOutputsModifiable() {
        return modifiable == null ? null : (modifiable & (byte)0x02) > 0;
    }

    public void setOutputsModifiable(boolean outputsModifiable) {
        if(modifiable != null) {
            modifiable = outputsModifiable ? (byte)(modifiable | (byte)0x02) : (byte)(modifiable & (byte)0xFD);
        }
    }

    public Boolean isSigHashSingleSignaturePresent() {
        return modifiable == null ? null : (modifiable & (byte)0x04) > 0;
    }

    public void setSigHashSingleSignaturePresent(boolean sigHashSingleSignaturePresent) {
        if(modifiable != null) {
            modifiable = sigHashSingleSignaturePresent ? (byte)(modifiable | (byte)0x04) : (byte)(modifiable & (byte)0xFB);
        }
    }

    public Map<String, String> getGlobalProprietary() {
        return globalProprietary;
    }

    public String toString() {
        return Utils.bytesToHex(serialize());
    }

    public String toBase64String() {
        return toBase64String(true);
    }

    public String toBase64String(boolean includeXpubs) {
        return Base64.toBase64String(serialize(includeXpubs, true));
    }

    public void convertVersion(int version) {
        if(version < 0) {
            throw new IllegalArgumentException("Version must be zero or positive");
        }

        //Convert from PSBTv2+ to PSBTv0
        if(getPsbtVersion() >= 2 && version == 0) {
            this.transaction = getTransaction();
            this.txVersion = null;
            this.fallbackLocktime = null;
            this.inputCount = null;
            this.outputCount = null;
            this.modifiable = null;

            for(PSBTInput psbtInput : getPsbtInputs()) {
                psbtInput.setPrevTxid(null);
                psbtInput.setPrevIndex(null);
                psbtInput.setSequence(null);
                psbtInput.setRequiredTimeLocktime(null);
                psbtInput.setRequiredHeightLocktime(null);
            }

            for(PSBTOutput psbtOutput : getPsbtOutputs()) {
                psbtOutput.setAmount(null);
                psbtOutput.setScript(null);
            }
        }

        //Convert from PSBTv0 to PSBTv2+
        if(getPsbtVersion() == 0 && version >= 2) {
            this.txVersion = transaction.getVersion();
            this.fallbackLocktime = transaction.getLocktime();
            this.inputCount = (long)transaction.getInputs().size();
            this.outputCount = (long)transaction.getOutputs().size();
            this.modifiable = null;

            for(PSBTInput psbtInput : getPsbtInputs()) {
                psbtInput.setPrevTxid(psbtInput.getPrevTxid());
                psbtInput.setPrevIndex(psbtInput.getPrevIndex());
                psbtInput.setSequence(psbtInput.getSequence());
                psbtInput.setRequiredTimeLocktime(null);
                psbtInput.setRequiredHeightLocktime(null);
            }

            for(PSBTOutput psbtOutput : getPsbtOutputs()) {
                psbtOutput.setAmount(psbtOutput.getAmount());
                psbtOutput.setScript(psbtOutput.getScript());
            }

            this.transaction = null;
        }

        this.version = version;
    }

    private long getLocktime(List<PSBTInput> psbtInputs, Long fallbackLocktime) {
        long fallback = (fallbackLocktime != null) ? fallbackLocktime : 0L;

        OptionalLong maxHeightLocktime = psbtInputs.stream().map(PSBTInput::getRequiredHeightLocktime).filter(Objects::nonNull).mapToLong(Long::longValue).max();
        OptionalLong maxTimeLocktime = psbtInputs.stream().map(PSBTInput::getRequiredTimeLocktime).filter(Objects::nonNull).mapToLong(Long::longValue).max();

        boolean allHeight = psbtInputs.stream().map(PSBTInput::getRequiredHeightLocktime).allMatch(Objects::nonNull);
        boolean allTime = psbtInputs.stream().map(PSBTInput::getRequiredTimeLocktime).allMatch(Objects::nonNull);

        if(maxHeightLocktime.isEmpty() && maxTimeLocktime.isEmpty()) {
            return fallback;
        }

        if(maxHeightLocktime.isPresent() && allHeight) {
            return maxHeightLocktime.getAsLong();
        }

        if(maxTimeLocktime.isPresent() && allTime) {
            return maxTimeLocktime.getAsLong();
        }

        if(maxHeightLocktime.isPresent() && maxTimeLocktime.isPresent()) {
            return maxHeightLocktime.getAsLong();
        }

        return maxHeightLocktime.orElse(maxTimeLocktime.orElse(fallback));
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
        try {
            if(Utils.isHex(s) && s.startsWith(PSBT_MAGIC_HEX)) {
                return true;
            } else {
                return Utils.isBase64(s) && Utils.bytesToHex(Base64.decode(s)).startsWith(PSBT_MAGIC_HEX);
            }
        } catch(Exception e) {
            //ignore
        }

        return false;
    }

    public static PSBT fromString(String strPSBT) throws PSBTParseException {
        return fromString(strPSBT, true);
    }

    public static PSBT fromString(String strPSBT, boolean verifySignatures) throws PSBTParseException {
        if (!isPSBT(strPSBT)) {
            throw new PSBTParseException("Provided string is not a PSBT");
        }

        if (Utils.isBase64(strPSBT) && !Utils.isHex(strPSBT)) {
            strPSBT = Utils.bytesToHex(Base64.decode(strPSBT));
        }

        byte[] psbtBytes = Utils.hexToBytes(strPSBT);
        return new PSBT(psbtBytes, verifySignatures);
    }
}
