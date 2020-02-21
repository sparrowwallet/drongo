package com.craigraw.drongo.psbt;

import com.craigraw.drongo.ExtendedPublicKey;
import com.craigraw.drongo.KeyDerivation;
import com.craigraw.drongo.Utils;
import com.craigraw.drongo.crypto.ChildNumber;
import com.craigraw.drongo.crypto.ECKey;
import com.craigraw.drongo.crypto.LazyECPoint;
import com.craigraw.drongo.protocol.*;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;

public class PSBT {
    public static final byte PSBT_GLOBAL_UNSIGNED_TX = 0x00;
    public static final byte PSBT_GLOBAL_BIP32_PUBKEY = 0x01;
    public static final byte PSBT_GLOBAL_VERSION = (byte)0xfb;
    public static final byte PSBT_GLOBAL_PROPRIETARY = (byte)0xfc;

    public static final byte PSBT_IN_NON_WITNESS_UTXO = 0x00;
    public static final byte PSBT_IN_WITNESS_UTXO = 0x01;
    public static final byte PSBT_IN_PARTIAL_SIG = 0x02;
    public static final byte PSBT_IN_SIGHASH_TYPE = 0x03;
    public static final byte PSBT_IN_REDEEM_SCRIPT = 0x04;
    public static final byte PSBT_IN_WITNESS_SCRIPT = 0x05;
    public static final byte PSBT_IN_BIP32_DERIVATION = 0x06;
    public static final byte PSBT_IN_FINAL_SCRIPTSIG = 0x07;
    public static final byte PSBT_IN_FINAL_SCRIPTWITNESS = 0x08;
    public static final byte PSBT_IN_POR_COMMITMENT = 0x09;
    public static final byte PSBT_IN_PROPRIETARY = (byte)0xfc;

    public static final byte PSBT_OUT_REDEEM_SCRIPT = 0x00;
    public static final byte PSBT_OUT_WITNESS_SCRIPT = 0x01;
    public static final byte PSBT_OUT_BIP32_DERIVATION = 0x02;
    public static final byte PSBT_OUT_PROPRIETARY = (byte)0xfc;

    public static final String PSBT_MAGIC = "70736274";

    private static final int STATE_GLOBALS = 1;
    private static final int STATE_INPUTS = 2;
    private static final int STATE_OUTPUTS = 3;
    private static final int STATE_END = 4;

    private static final int HARDENED = 0x80000000;

    private int inputs = 0;
    private int outputs = 0;
    private boolean parseOK = false;

    private String strPSBT = null;
    private byte[] psbtBytes = null;
    private ByteBuffer psbtByteBuffer = null;

    private Transaction transaction = null;
    private Integer version = null;
    private Map<ExtendedPublicKey, KeyDerivation> extendedPublicKeys = new LinkedHashMap<>();
    private Map<String, String> globalProprietary = new LinkedHashMap<>();

    private List<PSBTInput> psbtInputs = new ArrayList<>();
    private List<PSBTOutput> psbtOutputs = new ArrayList<>();

    private static final Logger log = LoggerFactory.getLogger(PSBT.class);

    public PSBT(String strPSBT) throws Exception {
        if (!isPSBT(strPSBT)) {
            log.debug("Provided string is not a PSBT");
            return;
        }

        if (Utils.isBase64(strPSBT) && !Utils.isHex(strPSBT)) {
            this.strPSBT = Hex.toHexString(Base64.decode(strPSBT));
        } else {
            this.strPSBT = strPSBT;
        }

        psbtBytes = Hex.decode(this.strPSBT);
        psbtByteBuffer = ByteBuffer.wrap(psbtBytes);

        read();
    }

    public PSBT(byte[] psbt) throws Exception {
        this(Hex.toHexString(psbt));
    }

    public void read() throws Exception {
        int seenInputs = 0;
        int seenOutputs = 0;

        psbtBytes = Hex.decode(strPSBT);
        psbtByteBuffer = ByteBuffer.wrap(psbtBytes);

        log.debug("--- ***** START ***** ---");
        log.debug("---  PSBT length:" + psbtBytes.length + "---");
        log.debug("--- parsing header ---");

        byte[] magicBuf = new byte[4];
        psbtByteBuffer.get(magicBuf);
        if (!PSBT.PSBT_MAGIC.equalsIgnoreCase(Hex.toHexString(magicBuf))) {
            throw new Exception("Invalid magic value");
        }

        byte sep = psbtByteBuffer.get();
        if (sep != (byte) 0xff) {
            throw new Exception("Bad 0xff separator:" + Hex.toHexString(new byte[]{sep}));
        }

        int currentState = STATE_GLOBALS;
        PSBTInput currentInput = new PSBTInput();
        PSBTOutput currentOutput = new PSBTOutput();

        while (psbtByteBuffer.hasRemaining()) {
            if (currentState == STATE_GLOBALS) {
                log.debug("--- parsing globals ---");
            } else if (currentState == STATE_INPUTS) {
                log.debug("--- parsing inputs ---");
            } else if (currentState == STATE_OUTPUTS) {
                log.debug("--- parsing outputs ---");
            }

            PSBTEntry entry = parse();
            if (entry == null) {
                log.debug("PSBT parse returned null entry");
            }

            if (entry.getKey() == null) {         // length == 0
                switch (currentState) {
                    case STATE_GLOBALS:
                        currentState = STATE_INPUTS;
                        break;
                    case STATE_INPUTS:
                        psbtInputs.add(currentInput);
                        currentInput = new PSBTInput();

                        seenInputs++;
                        if (seenInputs == inputs) {
                            currentState = STATE_OUTPUTS;
                        }
                        break;
                    case STATE_OUTPUTS:
                        psbtOutputs.add(currentOutput);
                        currentOutput = new PSBTOutput();

                        seenOutputs++;
                        if (seenOutputs == outputs) {
                            currentState = STATE_END;
                        }
                        break;
                    case STATE_END:
                        parseOK = true;
                        break;
                    default:
                        log.debug("PSBT read is in unknown state");
                        break;
                }
            } else if (currentState == STATE_GLOBALS) {
                switch (entry.getKeyType()[0]) {
                    case PSBT.PSBT_GLOBAL_UNSIGNED_TX:
                        Transaction transaction = new Transaction(entry.getData());
                        inputs = transaction.getInputs().size();
                        outputs = transaction.getOutputs().size();
                        log.debug("Transaction with txid: " + transaction.getTxId() + " version " + transaction.getVersion() + " size " + transaction.getMessageSize() + " locktime " + transaction.getLockTime());
                        for(TransactionInput input: transaction.getInputs()) {
                            log.debug(" Transaction input references txid: " + input.getOutpoint().getHash() + " vout " + input.getOutpoint().getIndex() + " with script " + input.getScript());
                        }
                        for(TransactionOutput output: transaction.getOutputs()) {
                            log.debug(" Transaction output value: " + output.getValue() + " to addresses " + Arrays.asList(output.getScript().getToAddresses()) + " with script hex " + Hex.toHexString(output.getScript().getProgram()) + " to script " + output.getScript());
                        }
                        setTransaction(transaction);
                        break;
                    case PSBT.PSBT_GLOBAL_BIP32_PUBKEY:
                        KeyDerivation keyDerivation = parseKeyDerivation(entry.getData());
                        ExtendedPublicKey pubKey = ExtendedPublicKey.fromDescriptor(keyDerivation.getMasterFingerprint(), keyDerivation.getDerivationPath(), Base58.encodeChecked(entry.getKeyData()), null);
                        addExtendedPublicKey(pubKey, keyDerivation);
                        log.debug("Pubkey with master fingerprint " + pubKey.getMasterFingerprint() + " at path " + pubKey.getKeyDerivationPath() + ": " + pubKey.getExtendedPublicKey());
                        break;
                    case PSBT.PSBT_GLOBAL_VERSION:
                        int version = (int)Utils.readUint32(entry.getData(), 0);
                        setVersion(version);
                        log.debug("PSBT version: " + version);
                        break;
                    case PSBT.PSBT_GLOBAL_PROPRIETARY:
                        addProprietary(Hex.toHexString(entry.getKeyData()), Hex.toHexString(entry.getData()));
                        log.debug("PSBT global proprietary data: " + Hex.toHexString(entry.getData()));
                        break;
                    default:
                        log.debug("PSBT global not recognized key type: " + entry.getKeyType()[0]);
                        break;
                }
            } else if (currentState == STATE_INPUTS) {
                switch (entry.getKeyType()[0]) {
                    case PSBT.PSBT_IN_NON_WITNESS_UTXO:
                        Transaction nonWitnessTx = new Transaction(entry.getData());
                        currentInput.setNonWitnessUtxo(nonWitnessTx);
                        log.debug("Found input non witness utxo with txid: " + nonWitnessTx.getTxId() + " version " + nonWitnessTx.getVersion() + " size " + nonWitnessTx.getMessageSize() + " locktime " + nonWitnessTx.getLockTime());
                        for(TransactionInput input: nonWitnessTx.getInputs()) {
                            log.debug(" Transaction input references txid: " + input.getOutpoint().getHash() + " vout " + input.getOutpoint().getIndex() + " with script " + input.getScript());
                        }
                        for(TransactionOutput output: nonWitnessTx.getOutputs()) {
                            log.debug(" Transaction output value: " + output.getValue() + " to addresses " + Arrays.asList(output.getScript().getToAddresses()) + " with script hex " + Hex.toHexString(output.getScript().getProgram()) + " to script " + output.getScript());
                        }
                        break;
                    case PSBT.PSBT_IN_WITNESS_UTXO:
                        TransactionOutput witnessTxOutput = new TransactionOutput(null, entry.getData(), 0);
                        currentInput.setWitnessUtxo(witnessTxOutput);
                        log.debug("Found input witness utxo amount " + witnessTxOutput.getValue() + " script hex " + Hex.toHexString(witnessTxOutput.getScript().getProgram()) + " script " + witnessTxOutput.getScript() + " addresses " + Arrays.asList(witnessTxOutput.getScript().getToAddresses()));
                        break;
                    case PSBT.PSBT_IN_PARTIAL_SIG:
                        LazyECPoint sigPublicKey = new LazyECPoint(ECKey.CURVE.getCurve(), entry.getKeyData());
                        currentInput.addPartialSignature(sigPublicKey, entry.getData());
                        log.debug("Found input partial signature with public key " + sigPublicKey + " signature " + Hex.toHexString(entry.getData()));
                        break;
                    case PSBT.PSBT_IN_SIGHASH_TYPE:
                        long sighashType = Utils.readUint32(entry.getData(), 0);
                        Transaction.SigHash sigHash = Transaction.SigHash.fromInt((int)sighashType);
                        currentInput.setSigHash(sigHash);
                        log.debug("Found input sighash_type " + sigHash.toString());
                        break;
                    case PSBT.PSBT_IN_REDEEM_SCRIPT:
                        Script redeemScript = new Script(entry.getData());
                        currentInput.setRedeemScript(redeemScript);
                        log.debug("Found input redeem script hex " + Hex.toHexString(redeemScript.getProgram()) + " script " + redeemScript);
                        break;
                    case PSBT.PSBT_IN_WITNESS_SCRIPT:
                        Script witnessScript = new Script(entry.getData());
                        currentInput.setWitnessScript(witnessScript);
                        log.debug("Found input witness script hex " + Hex.toHexString(witnessScript.getProgram()) + " script " + witnessScript);
                        break;
                    case PSBT.PSBT_IN_BIP32_DERIVATION:
                        LazyECPoint derivedPublicKey = new LazyECPoint(ECKey.CURVE.getCurve(), entry.getKeyData());
                        KeyDerivation keyDerivation = parseKeyDerivation(entry.getData());
                        currentInput.addDerivedPublicKey(derivedPublicKey, keyDerivation);
                        log.debug("Found input bip32_derivation with master fingerprint " + keyDerivation.getMasterFingerprint() + " at path " + keyDerivation.getDerivationPath() + " public key " + derivedPublicKey);
                        break;
                    case PSBT.PSBT_IN_FINAL_SCRIPTSIG:
                        Script finalScriptSig = new Script(entry.getData());
                        currentInput.setFinalScriptSig(finalScriptSig);
                        log.debug("Found input final scriptSig script hex " + Hex.toHexString(finalScriptSig.getProgram()) + " script " + finalScriptSig.toString());
                        break;
                    case PSBT.PSBT_IN_FINAL_SCRIPTWITNESS:
                        Script finalScriptWitness = new Script(entry.getData());
                        currentInput.setFinalScriptWitness(finalScriptWitness);
                        log.debug("Found input final scriptWitness script hex " + Hex.toHexString(finalScriptWitness.getProgram()) + " script " + finalScriptWitness.toString());
                        break;
                    case PSBT.PSBT_IN_POR_COMMITMENT:
                        String porMessage = new String(entry.getData(), "UTF-8");
                        currentInput.setPorCommitment(porMessage);
                        log.debug("Found input POR commitment message " + porMessage);
                        break;
                    case PSBT.PSBT_IN_PROPRIETARY:
                        currentInput.addProprietary(Hex.toHexString(entry.getKeyData()), Hex.toHexString(entry.getData()));
                        log.debug("Found proprietary input " + Hex.toHexString(entry.getKeyData()) + ": " + Hex.toHexString(entry.getData()));
                        break;
                    default:
                        log.debug("PSBT input not recognized key type:" + entry.getKeyType()[0]);
                        break;
                }
            } else if (currentState == STATE_OUTPUTS) {
                switch (entry.getKeyType()[0]) {
                    case PSBT.PSBT_OUT_REDEEM_SCRIPT:
                        Script redeemScript = new Script(entry.getData());
                        currentOutput.setRedeemScript(redeemScript);
                        log.debug("Found output redeem script hex " + Hex.toHexString(redeemScript.getProgram()) + " script " + redeemScript);
                        break;
                    case PSBT.PSBT_OUT_WITNESS_SCRIPT:
                        Script witnessScript = new Script(entry.getData());
                        currentOutput.setWitnessScript(witnessScript);
                        log.debug("Found output witness script hex " + Hex.toHexString(witnessScript.getProgram()) + " script " + witnessScript);
                        break;
                    case PSBT.PSBT_OUT_BIP32_DERIVATION:
                        LazyECPoint publicKey = new LazyECPoint(ECKey.CURVE.getCurve(), entry.getKeyData());
                        KeyDerivation keyDerivation = parseKeyDerivation(entry.getData());
                        currentOutput.addDerivedPublicKey(publicKey, keyDerivation);
                        log.debug("Found output bip32_derivation with master fingerprint " + keyDerivation.getMasterFingerprint() + " at path " + keyDerivation.getDerivationPath() + " public key " + publicKey);
                        break;
                    case PSBT.PSBT_OUT_PROPRIETARY:
                        currentOutput.addProprietary(Hex.toHexString(entry.getKeyData()), Hex.toHexString(entry.getData()));
                        log.debug("Found proprietary output " + Hex.toHexString(entry.getKeyData()) + ": " + Hex.toHexString(entry.getData()));
                        break;
                    default:
                        log.debug("PSBT output not recognized key type:" + entry.getKeyType()[0]);
                        break;
                }
            } else {
                log.debug("PSBT structure invalid");
            }

        }

        if (currentState == STATE_END) {
            log.debug("--- ***** END ***** ---");
        }
    }

    private PSBTEntry parse() {
        PSBTEntry entry = new PSBTEntry();

        try {
            int keyLen = PSBT.readCompactInt(psbtByteBuffer);
            log.debug("PSBT entry key length: " + keyLen);

            if (keyLen == 0x00) {
                log.debug("PSBT entry separator 0x00");
                return entry;
            }

            byte[] key = new byte[keyLen];
            psbtByteBuffer.get(key);
            log.debug("PSBT entry key: " + Hex.toHexString(key));

            byte[] keyType = new byte[1];
            keyType[0] = key[0];
            log.debug("PSBT entry key type: " + Hex.toHexString(keyType));

            byte[] keyData = null;
            if (key.length > 1) {
                keyData = new byte[key.length - 1];
                System.arraycopy(key, 1, keyData, 0, keyData.length);
                log.debug("PSBT entry key data: " + Hex.toHexString(keyData));
            }

            int dataLen = PSBT.readCompactInt(psbtByteBuffer);
            log.debug("PSBT entry data length: " + dataLen);

            byte[] data = new byte[dataLen];
            psbtByteBuffer.get(data);
            log.debug("PSBT entry data: " + Hex.toHexString(data));

            entry.setKey(key);
            entry.setKeyType(keyType);
            entry.setKeyData(keyData);
            entry.setData(data);

            return entry;

        } catch (Exception e) {
            log.debug("Error parsing PSBT entry", e);
            return null;
        }
    }

    private PSBTEntry populateEntry(byte type, byte[] keydata, byte[] data) throws Exception {
        PSBTEntry entry = new PSBTEntry();
        entry.setKeyType(new byte[]{type});
        entry.setKey(new byte[]{type});
        if (keydata != null) {
            entry.setKeyData(keydata);
        }
        entry.setData(data);

        return entry;
    }

    public byte[] serialize() throws IOException {
        ByteArrayOutputStream transactionbaos = new ByteArrayOutputStream();
        transaction.bitcoinSerialize(transactionbaos);
        byte[] serialized = transactionbaos.toByteArray();
        byte[] txLen = PSBT.writeCompactInt(serialized.length);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // magic
        baos.write(Hex.decode(PSBT.PSBT_MAGIC), 0, Hex.decode(PSBT.PSBT_MAGIC).length);
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
        strPSBT = Hex.toHexString(psbtBytes);
        log.debug("Wrote PSBT: " + strPSBT);

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

    public void setTransaction(Transaction transaction) {
        testIfNull(this.transaction);
        this.transaction = transaction;
    }

    public Integer getVersion() {
        return version;
    }

    public void setVersion(Integer version) {
        testIfNull(this.version);
        this.version = version;
    }

    public KeyDerivation getKeyDerivation(ExtendedPublicKey publicKey) {
        return extendedPublicKeys.get(publicKey);
    }

    public List<ExtendedPublicKey> getExtendedPublicKeys() {
        return new ArrayList<ExtendedPublicKey>(extendedPublicKeys.keySet());
    }

    public void addExtendedPublicKey(ExtendedPublicKey publicKey, KeyDerivation derivation) {
        if(extendedPublicKeys.containsKey(publicKey)) {
            throw new IllegalStateException("Duplicate public key in scope");
        }

        this.extendedPublicKeys.put(publicKey, derivation);
    }

    public void addProprietary(String key, String data) {
        globalProprietary.put(key, data);
    }

    private void testIfNull(Object obj) {
        if(obj != null) {
            throw new IllegalStateException("Duplicate keys in scope");
        }
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

    public KeyDerivation parseKeyDerivation(byte[] data) {
        String masterFingerprint = getMasterFingerprint(Arrays.copyOfRange(data, 0, 4));
        List<ChildNumber> bip32pathList = readBIP32Derivation(Arrays.copyOfRange(data, 4, data.length));
        String bip32path = KeyDerivation.writePath(bip32pathList);
        return new KeyDerivation(masterFingerprint, bip32path);
    }

    public static String getMasterFingerprint(byte[] data) {
        return Hex.toHexString(data);
    }

    public static List<ChildNumber> readBIP32Derivation(byte[] data) {
        List<ChildNumber> path = new ArrayList<>();

        ByteBuffer bb = ByteBuffer.wrap(data);
        byte[] buf = new byte[4];

        do {
            bb.get(buf);
            reverse(buf);
            ByteBuffer pbuf = ByteBuffer.wrap(buf);
            path.add(new ChildNumber(pbuf.getInt()));
        } while(bb.hasRemaining());

        return path;
    }

    private static void reverse(byte[] array) {
        for (int i = 0; i < array.length / 2; i++) {
            byte temp = array[i];
            array[i] = array[array.length - i - 1];
            array[array.length - i - 1] = temp;
        }
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
        if (Utils.isHex(s) && s.startsWith(PSBT.PSBT_MAGIC)) {
            return true;
        } else if (Utils.isBase64(s) && Hex.toHexString(Base64.decode(s)).startsWith(PSBT.PSBT_MAGIC)) {
            return true;
        } else {
            return false;
        }
    }

    public static void main(String[] args) throws Exception {
        String psbtBase64 = "cHNidP8BAMkCAAAAA3lxWr8zSZt5tiGZegyFWmd8b62cew6qi/4rTZGGif8OAAAAAAD/////td4T4zmwdQ8R2SbwRjRj+alAy1VX8mYZD2o9ZmefNIsAAAAAAP////+k9Xvvp9Lpap1TWd51NWu+MIfojG+MCqmguPyjII+5YgAAAAAA/////wKMz/AIAAAAABl2qRSE7GtWKUoaFcVQ8n9qfMYi41Yh0YisjM/wCAAAAAAZdqkUmka3O8TiIRG8h+a1mDLFQVTfJEiIrAAAAAAAAQBVAgAAAAGt3gAAAAAAAO++AAAAAAAAAAAAAAAAAAAAAAAAAAAAAEkAAAAA/////wEA4fUFAAAAABl2qRSvQiRNb8B3El3G+KdspA3+DRvH1IisAAAAACIGA383lPO+TErMCGrITWkCwCVxPqv4iQ8g9ErPCzTjwPD3DHSXSzsAAAAAAAAAAAABAFUCAAAAAa3eAAAAAAAA774AAAAAAAAAAAAAAAAAAAAAAAAAAAAASQAAAAD/////AQDh9QUAAAAAGXapFAn8nw1IXPh34v8wuhJrcu34Xg8qiKwAAAAAIgYDTr6iJ7sP/u+0gz4wi+Muuc4IxEoJaGYedN/uqwmSfbgMdJdLOwAAAAABAAAAAAEAVQIAAAABrd4AAAAAAADvvgAAAAAAAAAAAAAAAAAAAAAAAAAAAABJAAAAAP////8BAOH1BQAAAAAZdqkUGMIzFJsgyFIYzDbThZ5S2zTnvRiIrAAAAAAiBgK7oYu+Z/kEK6XK3urdEDW2ngkwnXD1gZBjEgRW0wD7Igx0l0s7AAAAAAIAAAAAACICAyw+nsM8JYHohVqRsQ2qilEwjZPh+OkGPqkO2kYZczCZEHSXSzsMAAAAIgAAADcBAAAA";

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
            psbt = new PSBT(psbtBase64);
        }

        System.out.println(psbt);
    }
}
