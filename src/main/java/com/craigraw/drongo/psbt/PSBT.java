package com.craigraw.drongo.psbt;

import com.craigraw.drongo.ExtendedPublicKey;
import com.craigraw.drongo.KeyDerivation;
import com.craigraw.drongo.Utils;
import com.craigraw.drongo.protocol.*;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;

import static com.craigraw.drongo.psbt.PSBTEntry.parseKeyDerivation;

public class PSBT {
    public static final byte PSBT_GLOBAL_UNSIGNED_TX = 0x00;
    public static final byte PSBT_GLOBAL_BIP32_PUBKEY = 0x01;
    public static final byte PSBT_GLOBAL_VERSION = (byte)0xfb;
    public static final byte PSBT_GLOBAL_PROPRIETARY = (byte)0xfc;

    public static final String PSBT_MAGIC = "70736274";

    private static final int STATE_GLOBALS = 1;
    private static final int STATE_INPUTS = 2;
    private static final int STATE_OUTPUTS = 3;
    private static final int STATE_END = 4;

    private static final int HARDENED = 0x80000000;

    private int inputs = 0;
    private int outputs = 0;

    private byte[] psbtBytes;

    private Transaction transaction = null;
    private Integer version = null;
    private Map<ExtendedPublicKey, KeyDerivation> extendedPublicKeys = new LinkedHashMap<>();
    private Map<String, String> globalProprietary = new LinkedHashMap<>();

    private List<PSBTInput> psbtInputs = new ArrayList<>();
    private List<PSBTOutput> psbtOutputs = new ArrayList<>();

    private static final Logger log = LoggerFactory.getLogger(PSBT.class);

    public PSBT(byte[] psbt) {
        this.psbtBytes = psbt;
        parse();
    }

    private void parse() {
        int seenInputs = 0;
        int seenOutputs = 0;

        ByteBuffer psbtByteBuffer = ByteBuffer.wrap(psbtBytes);

        byte[] magicBuf = new byte[4];
        psbtByteBuffer.get(magicBuf);
        if (!PSBT_MAGIC.equalsIgnoreCase(Hex.toHexString(magicBuf))) {
            throw new IllegalStateException("PSBT has invalid magic value");
        }

        byte sep = psbtByteBuffer.get();
        if (sep != (byte) 0xff) {
            throw new IllegalStateException("PSBT has bad initial separator:" + Hex.toHexString(new byte[]{sep}));
        }

        int currentState = STATE_GLOBALS;
        List<PSBTEntry> globalEntries = new ArrayList<>();
        List<List<PSBTEntry>> inputEntryLists = new ArrayList<>();
        List<List<PSBTEntry>> outputEntryLists = new ArrayList<>();

        List<PSBTEntry> inputEntries = new ArrayList<>();
        List<PSBTEntry> outputEntries = new ArrayList<>();

        while (psbtByteBuffer.hasRemaining()) {
            PSBTEntry entry = parseEntry(psbtByteBuffer);

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
                        throw new IllegalStateException("PSBT read is in unknown state");
                }
            } else if (currentState == STATE_GLOBALS) {
                globalEntries.add(entry);
            } else if (currentState == STATE_INPUTS) {
                inputEntries.add(entry);
            } else if (currentState == STATE_OUTPUTS) {
                outputEntries.add(entry);
            } else {
                throw new IllegalStateException("PSBT structure invalid");
            }
        }

        if(currentState != STATE_END) {
            if(transaction == null) {
                throw new IllegalStateException("Missing transaction");
            }

            if(currentState == STATE_INPUTS) {
                throw new IllegalStateException("Missing inputs");
            }

            if(currentState == STATE_OUTPUTS) {
                throw new IllegalStateException("Missing outputs");
            }
        }

        log.debug("Calculated fee at " + getFee());
    }

    private PSBTEntry parseEntry(ByteBuffer psbtByteBuffer) {
        PSBTEntry entry = new PSBTEntry();

        try {
            int keyLen = PSBT.readCompactInt(psbtByteBuffer);

            if (keyLen == 0x00) {
                return entry;
            }

            byte[] key = new byte[keyLen];
            psbtByteBuffer.get(key);

            byte keyType = key[0];

            byte[] keyData = null;
            if (key.length > 1) {
                keyData = new byte[key.length - 1];
                System.arraycopy(key, 1, keyData, 0, keyData.length);
            }

            int dataLen = PSBT.readCompactInt(psbtByteBuffer);
            byte[] data = new byte[dataLen];
            psbtByteBuffer.get(data);

            entry.setKey(key);
            entry.setKeyType(keyType);
            entry.setKeyData(keyData);
            entry.setData(data);

            return entry;

        } catch (Exception e) {
            throw new IllegalStateException("Error parsing PSBT entry", e);
        }
    }

    private PSBTEntry populateEntry(byte type, byte[] keydata, byte[] data) throws Exception {
        PSBTEntry entry = new PSBTEntry();
        entry.setKeyType(type);
        entry.setKey(new byte[]{type});
        if (keydata != null) {
            entry.setKeyData(keydata);
        }
        entry.setData(data);

        return entry;
    }

    private void parseGlobalEntries(List<PSBTEntry> globalEntries) {
        PSBTEntry duplicate = findDuplicateKey(globalEntries);
        if(duplicate != null) {
            throw new IllegalStateException("Found duplicate key for PSBT global: " + Hex.toHexString(duplicate.getKey()));
        }

        for(PSBTEntry entry : globalEntries) {
            switch(entry.getKeyType()) {
                case PSBT_GLOBAL_UNSIGNED_TX:
                    entry.checkOneByteKey();
                    Transaction transaction = new Transaction(entry.getData());
                    inputs = transaction.getInputs().size();
                    outputs = transaction.getOutputs().size();
                    log.debug("Transaction with txid: " + transaction.getTxId() + " version " + transaction.getVersion() + " size " + transaction.getMessageSize() + " locktime " + transaction.getLockTime());
                    for(TransactionInput input: transaction.getInputs()) {
                        if(input.getScript().getProgram().length != 0) {
                            throw new IllegalStateException("Unsigned tx input does not have empty scriptSig");
                        }
                        log.debug(" Transaction input references txid: " + input.getOutpoint().getHash() + " vout " + input.getOutpoint().getIndex() + " with script " + input.getScript());
                    }
                    for(TransactionOutput output: transaction.getOutputs()) {
                        try {
                            log.debug(" Transaction output value: " + output.getValue() + " to addresses " + Arrays.asList(output.getScript().getToAddresses()) + " with script hex " + Hex.toHexString(output.getScript().getProgram()) + " to script " + output.getScript());
                        } catch(ProtocolException e) {
                            log.debug(" Transaction output value: " + output.getValue() + " with script hex " + Hex.toHexString(output.getScript().getProgram()) + " to script " + output.getScript());
                        }
                    }
                    this.transaction = transaction;
                    break;
                case PSBT_GLOBAL_BIP32_PUBKEY:
                    entry.checkOneBytePlusXpubKey();
                    KeyDerivation keyDerivation = parseKeyDerivation(entry.getData());
                    ExtendedPublicKey pubKey = ExtendedPublicKey.fromDescriptor(keyDerivation.getMasterFingerprint(), keyDerivation.getDerivationPath(), Base58.encodeChecked(entry.getKeyData()), null);
                    this.extendedPublicKeys.put(pubKey, keyDerivation);
                    log.debug("Pubkey with master fingerprint " + pubKey.getMasterFingerprint() + " at path " + pubKey.getKeyDerivationPath() + ": " + pubKey.getExtendedPublicKey());
                    break;
                case PSBT_GLOBAL_VERSION:
                    entry.checkOneByteKey();
                    int version = (int)Utils.readUint32(entry.getData(), 0);
                    this.version = version;
                    log.debug("PSBT version: " + version);
                    break;
                case PSBT_GLOBAL_PROPRIETARY:
                    globalProprietary.put(Hex.toHexString(entry.getKeyData()), Hex.toHexString(entry.getData()));
                    log.debug("PSBT global proprietary data: " + Hex.toHexString(entry.getData()));
                    break;
                default:
                    log.warn("PSBT global not recognized key type: " + entry.getKeyType());
            }
        }
    }

    private void parseInputEntries(List<List<PSBTEntry>> inputEntryLists) {
        for(List<PSBTEntry> inputEntries : inputEntryLists) {
            PSBTEntry duplicate = findDuplicateKey(inputEntries);
            if(duplicate != null) {
                throw new IllegalStateException("Found duplicate key for PSBT input: " + Hex.toHexString(duplicate.getKey()));
            }

            PSBTInput input = new PSBTInput(inputEntries, transaction, this.psbtInputs.size());
            this.psbtInputs.add(input);
        }
    }

    private void parseOutputEntries(List<List<PSBTEntry>> outputEntryLists) {
        for(List<PSBTEntry> outputEntries : outputEntryLists) {
            PSBTEntry duplicate = findDuplicateKey(outputEntries);
            if(duplicate != null) {
                throw new IllegalStateException("Found duplicate key for PSBT output: " + Hex.toHexString(duplicate.getKey()));
            }

            PSBTOutput output = new PSBTOutput(outputEntries);
            this.psbtOutputs.add(output);
        }
    }

    private PSBTEntry findDuplicateKey(List<PSBTEntry> entries) {
        Set checkSet = new HashSet();
        for(PSBTEntry entry: entries) {
            if(!checkSet.add(Hex.toHexString(entry.getKey())) ) {
                return entry;
            }
        }

        return null;
    }

    public Long getFee() {
        long fee = 0L;

        for (int i = 0; i < psbtInputs.size(); i++) {
            PSBTInput input = psbtInputs.get(i);
            if(input.getNonWitnessUtxo() != null) {
                int index = (int)transaction.getInputs().get(i).getOutpoint().getIndex();
                fee += input.getNonWitnessUtxo().getOutputs().get(index).getValue();
            } else if(input.getWitnessUtxo() != null) {
                fee += input.getWitnessUtxo().getValue();
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

    public byte[] serialize() throws IOException {
        ByteArrayOutputStream transactionbaos = new ByteArrayOutputStream();
        transaction.bitcoinSerialize(transactionbaos);
        byte[] serialized = transactionbaos.toByteArray();
        byte[] txLen = PSBT.writeCompactInt(serialized.length);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // magic
        baos.write(Hex.decode(PSBT_MAGIC), 0, Hex.decode(PSBT_MAGIC).length);
        // separator
        baos.write((byte) 0xff);

        // globals
        baos.write(writeCompactInt(1L));                                // key length
        baos.write((byte) 0x00);                                             // key
        baos.write(txLen, 0, txLen.length);                             // value length
        baos.write(serialized, 0, serialized.length);                   // value
        baos.write((byte) 0x00);

        // inputs
//        for (PSBTEntry entry : psbtInputs) {
//            int keyLen = 1;
//            if (entry.getKeyData() != null) {
//                keyLen += entry.getKeyData().length;
//            }
//            baos.write(writeCompactInt(keyLen));
//            baos.write(entry.getKey());
//            if (entry.getKeyData() != null) {
//                baos.write(entry.getKeyData());
//            }
//            baos.write(writeCompactInt(entry.getData().length));
//            baos.write(entry.getData());
//        }
//        baos.write((byte) 0x00);
//
//        // outputs
//        for (PSBTEntry entry : psbtOutputs) {
//            int keyLen = 1;
//            if (entry.getKeyData() != null) {
//                keyLen += entry.getKeyData().length;
//            }
//            baos.write(writeCompactInt(keyLen));
//            baos.write(entry.getKey());
//            if (entry.getKeyData() != null) {
//                baos.write(entry.getKeyData());
//            }
//            baos.write(writeCompactInt(entry.getData().length));
//            baos.write(entry.getData());
//        }
        baos.write((byte) 0x00);

        // eof
        baos.write((byte) 0x00);

        psbtBytes = baos.toByteArray();

        return psbtBytes;
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

    public KeyDerivation getKeyDerivation(ExtendedPublicKey publicKey) {
        return extendedPublicKeys.get(publicKey);
    }

    public List<ExtendedPublicKey> getExtendedPublicKeys() {
        return new ArrayList<ExtendedPublicKey>(extendedPublicKeys.keySet());
    }

    public String toString() {
        try {
            return Hex.toHexString(serialize());
        } catch (IOException ioe) {
            return null;
        }
    }

    public String toBase64String() throws IOException {
        return Base64.toBase64String(serialize());
    }

    public static int readCompactInt(ByteBuffer psbtByteBuffer) throws Exception {
        byte b = psbtByteBuffer.get();

        switch (b) {
            case (byte) 0xfd: {
                byte[] buf = new byte[2];
                psbtByteBuffer.get(buf);
                ByteBuffer byteBuffer = ByteBuffer.wrap(buf);
                byteBuffer.order(ByteOrder.LITTLE_ENDIAN);
                return byteBuffer.getShort();
            }
            case (byte) 0xfe: {
                byte[] buf = new byte[4];
                psbtByteBuffer.get(buf);
                ByteBuffer byteBuffer = ByteBuffer.wrap(buf);
                byteBuffer.order(ByteOrder.LITTLE_ENDIAN);
                return byteBuffer.getInt();
            }
            case (byte) 0xff: {
                byte[] buf = new byte[8];
                psbtByteBuffer.get(buf);
                ByteBuffer byteBuffer = ByteBuffer.wrap(buf);
                byteBuffer.order(ByteOrder.LITTLE_ENDIAN);
                throw new Exception("Data too long:" + byteBuffer.getLong());
            }
            default:
                return (int) (b & 0xff);
        }

    }

    public static byte[] writeCompactInt(long val) {
        ByteBuffer bb = null;

        if (val < 0xfdL) {
            bb = ByteBuffer.allocate(1);
            bb.order(ByteOrder.LITTLE_ENDIAN);
            bb.put((byte) val);
        } else if (val < 0xffffL) {
            bb = ByteBuffer.allocate(3);
            bb.order(ByteOrder.LITTLE_ENDIAN);
            bb.put((byte) 0xfd);
            bb.put((byte) (val & 0xff));
            bb.put((byte) ((val >> 8) & 0xff));
        } else if (val < 0xffffffffL) {
            bb = ByteBuffer.allocate(5);
            bb.order(ByteOrder.LITTLE_ENDIAN);
            bb.put((byte) 0xfe);
            bb.putInt((int) val);
        } else {
            bb = ByteBuffer.allocate(9);
            bb.order(ByteOrder.LITTLE_ENDIAN);
            bb.put((byte) 0xff);
            bb.putLong(val);
        }

        return bb.array();
    }

    public static byte[] writeSegwitInputUTXO(long value, byte[] scriptPubKey) {

        byte[] ret = new byte[scriptPubKey.length + Long.BYTES];

        // long to byte array
        ByteBuffer xlat = ByteBuffer.allocate(Long.BYTES);
        xlat.order(ByteOrder.LITTLE_ENDIAN);
        xlat.putLong(0, value);
        byte[] val = new byte[Long.BYTES];
        xlat.get(val);

        System.arraycopy(val, 0, ret, 0, Long.BYTES);
        System.arraycopy(scriptPubKey, 0, ret, Long.BYTES, scriptPubKey.length);

        return ret;
    }

    public static byte[] writeBIP32Derivation(byte[] fingerprint, int purpose, int type, int account, int chain, int index) {
        // fingerprint and integer values to BIP32 derivation buffer
        byte[] bip32buf = new byte[24];

        System.arraycopy(fingerprint, 0, bip32buf, 0, fingerprint.length);

        ByteBuffer xlat = ByteBuffer.allocate(Integer.BYTES);
        xlat.order(ByteOrder.LITTLE_ENDIAN);
        xlat.putInt(0, purpose + HARDENED);
        byte[] out = new byte[Integer.BYTES];
        xlat.get(out);
        System.arraycopy(out, 0, bip32buf, fingerprint.length, out.length);

        xlat.clear();
        xlat.order(ByteOrder.LITTLE_ENDIAN);
        xlat.putInt(0, type + HARDENED);
        xlat.get(out);
        System.arraycopy(out, 0, bip32buf, fingerprint.length + out.length, out.length);

        xlat.clear();
        xlat.order(ByteOrder.LITTLE_ENDIAN);
        xlat.putInt(0, account + HARDENED);
        xlat.get(out);
        System.arraycopy(out, 0, bip32buf, fingerprint.length + (out.length * 2), out.length);

        xlat.clear();
        xlat.order(ByteOrder.LITTLE_ENDIAN);
        xlat.putInt(0, chain);
        xlat.get(out);
        System.arraycopy(out, 0, bip32buf, fingerprint.length + (out.length * 3), out.length);

        xlat.clear();
        xlat.order(ByteOrder.LITTLE_ENDIAN);
        xlat.putInt(0, index);
        xlat.get(out);
        System.arraycopy(out, 0, bip32buf, fingerprint.length + (out.length * 4), out.length);

        return bip32buf;
    }

    public static boolean isPSBT(String s) {
        if (Utils.isHex(s) && s.startsWith(PSBT_MAGIC)) {
            return true;
        } else if (Utils.isBase64(s) && Hex.toHexString(Base64.decode(s)).startsWith(PSBT_MAGIC)) {
            return true;
        } else {
            return false;
        }
    }

    public static PSBT fromString(String strPSBT) {
        if (!isPSBT(strPSBT)) {
            throw new IllegalArgumentException("Provided string is not a PSBT");
        }

        if (Utils.isBase64(strPSBT) && !Utils.isHex(strPSBT)) {
            strPSBT = Hex.toHexString(Base64.decode(strPSBT));
        }

        byte[] psbtBytes = Hex.decode(strPSBT);
        return new PSBT(psbtBytes);
    }

    public static void main(String[] args) throws Exception {
        String psbtBase64 = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHAQQiACCMI1MXN0O1ld+0oHtyuo5C43l9p06H/n2ddJfjsgKJAwEFR1IhAwidwQx6xttU+RMpr2FzM9s4jOrQwjH3IzedG5kDCwLcIQI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc1KuIgYCOt2QTz1tz1nduQaw3uI1Kbf/ue1Q5ehhUZJoYCIfDnMQ2QxqTwAAAIAAAACAAwAAgCIGAwidwQx6xttU+RMpr2FzM9s4jOrQwjH3IzedG5kDCwLcENkMak8AAACAAAAAgAIAAIAAIgIDqaTDf1mW06ol26xrVwrwZQOUSSlCRgs1R1Ptnuylh3EQ2QxqTwAAAIAAAACABAAAgAAiAgJ/Y5l1fS7/VaE2rQLGhLGDi2VW5fG2s0KCqUtrUAUQlhDZDGpPAAAAgAAAAIAFAACAAA==";

        PSBT psbt = null;
        String filename = "default.psbt";
        File psbtFile = new File(filename);
        if(psbtFile.exists()) {
            byte[] psbtBytes = new byte[(int)psbtFile.length()];
            FileInputStream stream = new FileInputStream(psbtFile);
            stream.read(psbtBytes);
            stream.close();
            psbt = new PSBT(psbtBytes);
        } else {
            psbt = PSBT.fromString(psbtBase64);
        }

        System.out.println(psbt);
    }
}
