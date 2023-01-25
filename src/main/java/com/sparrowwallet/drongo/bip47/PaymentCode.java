package com.sparrowwallet.drongo.bip47;

import com.sparrowwallet.drongo.address.Address;
import com.sparrowwallet.drongo.crypto.ChildNumber;
import com.sparrowwallet.drongo.crypto.DeterministicKey;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.crypto.HDKeyDerivation;
import com.sparrowwallet.drongo.protocol.*;
import com.sparrowwallet.drongo.wallet.Keystore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static com.sparrowwallet.drongo.Utils.xor;

public class PaymentCode {
    private static final Logger log = LoggerFactory.getLogger(PaymentCode.class);

    private static final int PUBLIC_KEY_Y_OFFSET = 2;
    private static final int PUBLIC_KEY_X_OFFSET = 3;
    private static final int CHAIN_OFFSET = 35;
    private static final int PUBLIC_KEY_X_LEN = 32;
    private static final int PUBLIC_KEY_Y_LEN = 1;
    private static final int CHAIN_LEN = 32;
    private static final int PAYLOAD_LEN = 80;

    private static final int SAMOURAI_FEATURE_BYTE = 79;
    private static final int SAMOURAI_SEGWIT_BIT = 0;

    private final String strPaymentCode;
    private final byte[] pubkey;
    private final byte[] chain;

    public static final List<ScriptType> SEGWIT_SCRIPT_TYPES = List.of(ScriptType.P2PKH, ScriptType.P2SH_P2WPKH, ScriptType.P2WPKH);
    public static final List<ScriptType> V1_SCRIPT_TYPES = List.of(ScriptType.P2PKH);

    private PaymentCode(String strPaymentCode, byte[] pubkey, byte[] chain) {
        this.strPaymentCode = strPaymentCode;
        this.pubkey = pubkey;
        this.chain = chain;
    }

    public PaymentCode(String payment_code) throws InvalidPaymentCodeException {
        strPaymentCode = payment_code;
        Map.Entry<byte[], byte[]> pubKeyChain = parse().entrySet().iterator().next();
        this.pubkey = pubKeyChain.getKey();
        this.chain = pubKeyChain.getValue();
    }

    public PaymentCode(byte[] payload) {
        if(payload.length != 80) {
            throw new IllegalArgumentException("Payment code must be 80 bytes");
        }

        pubkey = new byte[PUBLIC_KEY_Y_LEN + PUBLIC_KEY_X_LEN];
        chain = new byte[CHAIN_LEN];

        System.arraycopy(payload, PUBLIC_KEY_Y_OFFSET, pubkey, 0, PUBLIC_KEY_Y_LEN + PUBLIC_KEY_X_LEN);
        System.arraycopy(payload, CHAIN_OFFSET, chain, 0, CHAIN_LEN);

        strPaymentCode = makeV1();
    }

    public PaymentCode(byte[] pubkey, byte[] chain) {
        this.pubkey = pubkey;
        this.chain = chain;
        strPaymentCode = makeV1();
    }

    public ECKey getNotificationKey() {
        DeterministicKey masterPubKey = createMasterPubKeyFromBytes();
        return HDKeyDerivation.deriveChildKey(masterPubKey, ChildNumber.ZERO);
    }

    public Address getNotificationAddress() {
        return ScriptType.P2PKH.getAddress(getNotificationKey());
    }

    public ECKey getKey(int index) {
        DeterministicKey masterPubKey = createMasterPubKeyFromBytes();
        return HDKeyDerivation.deriveChildKey(masterPubKey, new ChildNumber(index));
    }

    public byte[] getPayload() {
        byte[] pcBytes = Base58.decodeChecked(strPaymentCode);
        byte[] payload = new byte[PAYLOAD_LEN];
        System.arraycopy(pcBytes, 1, payload, 0, payload.length);

        return payload;
    }

    public int getType() throws InvalidPaymentCodeException {
        byte[] payload = getPayload();
        ByteBuffer bb = ByteBuffer.wrap(payload);
        return bb.get();
    }

    public boolean isSegwitEnabled() {
        return isBitSet(getPayload()[SAMOURAI_FEATURE_BYTE], SAMOURAI_SEGWIT_BIT);
    }

    public String toString() {
        return strPaymentCode;
    }

    public static PaymentCode getPaymentCode(Transaction transaction, Keystore keystore) throws InvalidPaymentCodeException {
        try {
            TransactionInput txInput = getDesignatedInput(transaction);
            ECKey pubKey = getDesignatedPubKey(txInput);

            List<ChildNumber> derivation = keystore.getKeyDerivation().getDerivation();
            ChildNumber derivationStart = derivation.isEmpty() ? ChildNumber.ZERO_HARDENED : derivation.get(derivation.size() - 1);
            ECKey notificationPrivKey = keystore.getBip47ExtendedPrivateKey().getKey(List.of(derivationStart, new ChildNumber(0)));
            SecretPoint secretPoint = new SecretPoint(notificationPrivKey.getPrivKeyBytes(), pubKey.getPubKey());
            byte[] blindingMask = getMask(secretPoint.ECDHSecretAsBytes(), txInput.getOutpoint().bitcoinSerialize());
            byte[] blindedPaymentCode = getOpReturnData(transaction);
            return new PaymentCode(PaymentCode.blind(blindedPaymentCode, blindingMask));
        } catch(Exception e) {
            throw new InvalidPaymentCodeException("Could not determine payment code from transaction", e);
        }
    }

    public static TransactionInput getDesignatedInput(Transaction transaction) {
        for(TransactionInput txInput : transaction.getInputs()) {
            if(getDesignatedPubKey(txInput) != null) {
                return txInput;
            }
        }

        throw new IllegalArgumentException("Cannot find designated input in notification transaction");
    }

    private static ECKey getDesignatedPubKey(TransactionInput txInput) {
        for(ScriptChunk scriptChunk : txInput.getScriptSig().getChunks()) {
            if(scriptChunk.isPubKey()) {
                return scriptChunk.getPubKey();
            }
        }

        for(ScriptChunk scriptChunk : txInput.getWitness().asScriptChunks()) {
            if(scriptChunk.isPubKey()) {
                return scriptChunk.getPubKey();
            }
        }

        return null;
    }

    public static byte[] getOpReturnData(Transaction transaction) {
        for(TransactionOutput txOutput : transaction.getOutputs()) {
            List<ScriptChunk> scriptChunks = getOpReturnChunks(txOutput);
            if(scriptChunks == null) {
                continue;
            }

            return scriptChunks.get(1).getData();
        }

        throw new IllegalArgumentException("Cannot find OP_RETURN output in notification transaction");
    }

    private static List<ScriptChunk> getOpReturnChunks(TransactionOutput txOutput) {
        List<ScriptChunk> scriptChunks = txOutput.getScript().getChunks();
        if(scriptChunks.size() != 2) {
            return null;
        }
        if(scriptChunks.get(0).getOpcode() != ScriptOpCodes.OP_RETURN) {
            return null;
        }
        if(scriptChunks.get(1).getData() != null && scriptChunks.get(1).getData().length != 80) {
            return null;
        }
        byte[] data = scriptChunks.get(1).getData();
        if(data[0] != 0x01 || (data[2] != 0x02 && data[2] != 0x03)) {
            return null;
        }
        return scriptChunks;
    }

    public static byte[] getMask(byte[] sPoint, byte[] oPoint) {
        Mac sha512_HMAC;
        byte[] mac_data = null;

        try {
            sha512_HMAC = Mac.getInstance("HmacSHA512");
            SecretKeySpec secretkey = new SecretKeySpec(oPoint, "HmacSHA512");
            sha512_HMAC.init(secretkey);
            mac_data = sha512_HMAC.doFinal(sPoint);
        } catch(InvalidKeyException | NoSuchAlgorithmException ignored) {
            //ignore
        }

        return mac_data;
    }

    public static byte[] blind(byte[] payload, byte[] mask) throws InvalidPaymentCodeException {
        byte[] ret = new byte[PAYLOAD_LEN];
        byte[] pubkey = new byte[PUBLIC_KEY_X_LEN];
        byte[] chain = new byte[CHAIN_LEN];
        byte[] buf0 = new byte[PUBLIC_KEY_X_LEN];
        byte[] buf1 = new byte[CHAIN_LEN];

        System.arraycopy(payload, 0, ret, 0, PAYLOAD_LEN);

        System.arraycopy(payload, PUBLIC_KEY_X_OFFSET, pubkey, 0, PUBLIC_KEY_X_LEN);
        System.arraycopy(payload, CHAIN_OFFSET, chain, 0, CHAIN_LEN);
        System.arraycopy(mask, 0, buf0, 0, PUBLIC_KEY_X_LEN);
        System.arraycopy(mask, PUBLIC_KEY_X_LEN, buf1, 0, CHAIN_LEN);

        System.arraycopy(xor(pubkey, buf0), 0, ret, PUBLIC_KEY_X_OFFSET, PUBLIC_KEY_X_LEN);
        System.arraycopy(xor(chain, buf1), 0, ret, CHAIN_OFFSET, CHAIN_LEN);

        return ret;
    }

    private Map<byte[], byte[]> parse() throws InvalidPaymentCodeException {
        byte[] pcBytes = Base58.decodeChecked(strPaymentCode);

        ByteBuffer bb = ByteBuffer.wrap(pcBytes);
        if(bb.get() != 0x47) {
            throw new InvalidPaymentCodeException("Invalid payment code version");
        }

        byte[] chain = new byte[CHAIN_LEN];
        byte[] pub = new byte[PUBLIC_KEY_X_LEN + PUBLIC_KEY_Y_LEN];

        // type:
        bb.get();
        // features:
        bb.get();

        bb.get(pub);
        if(pub[0] != 0x02 && pub[0] != 0x03) {
            throw new InvalidPaymentCodeException("Invalid public key");
        }

        bb.get(chain);

        return Map.of(pub, chain);
    }

    private String makeV1() {
        return make(0x01);
    }

    private String make(int type) {
        byte[] payload = new byte[PAYLOAD_LEN];
        byte[] payment_code = new byte[PAYLOAD_LEN + 1];

        for(int i = 0; i < payload.length; i++) {
            payload[i] = (byte) 0x00;
        }

        // byte 0: type.
        payload[0] = (byte) type;
        // byte 1: features bit field. All bits must be zero except where specified elsewhere in this specification
        //      bit 0: Bitmessage notification
        //      bits 1-7: reserved
        payload[1] = (byte) 0x00;

        // replace sign & x code (33 bytes)
        System.arraycopy(pubkey, 0, payload, PUBLIC_KEY_Y_OFFSET, pubkey.length);
        // replace chain code (32 bytes)
        System.arraycopy(chain, 0, payload, CHAIN_OFFSET, chain.length);

        // add version byte
        payment_code[0] = (byte) 0x47;
        System.arraycopy(payload, 0, payment_code, 1, payload.length);

        // append checksum
        return base58EncodeChecked(payment_code);
    }

    public String makeSamouraiPaymentCode() throws InvalidPaymentCodeException {
        byte[] payload = getPayload();
        // set bit0 = 1 in 'Samourai byte' for segwit. Can send/receive P2PKH, P2SH-P2WPKH, P2WPKH (bech32)
        payload[SAMOURAI_FEATURE_BYTE] = setBit(payload[SAMOURAI_FEATURE_BYTE], SAMOURAI_SEGWIT_BIT);
        byte[] payment_code = new byte[PAYLOAD_LEN + 1];
        // add version byte
        payment_code[0] = (byte) 0x47;
        System.arraycopy(payload, 0, payment_code, 1, payload.length);

        // append checksum
        return base58EncodeChecked(payment_code);
    }

    private String base58EncodeChecked(byte[] buf) {
        byte[] checksum = Arrays.copyOfRange(Sha256Hash.hashTwice(buf), 0, 4);
        byte[] bufChecked = new byte[buf.length + checksum.length];
        System.arraycopy(buf, 0, bufChecked, 0, buf.length);
        System.arraycopy(checksum, 0, bufChecked, bufChecked.length - 4, checksum.length);

        return Base58.encode(bufChecked);
    }

    private boolean isBitSet(byte b, int pos) {
        byte test = 0;
        return (setBit(test, pos) & b) > 0;
    }

    private byte setBit(byte b, int pos) {
        return (byte) (b | (1 << pos));
    }

    private DeterministicKey createMasterPubKeyFromBytes() {
        return HDKeyDerivation.createMasterPubKeyFromBytes(pubkey, chain);
    }

    public boolean isValid() {
        try {
            byte[] pcodeBytes = Base58.decodeChecked(strPaymentCode);

            ByteBuffer byteBuffer = ByteBuffer.wrap(pcodeBytes);
            if(byteBuffer.get() != 0x47) {
                throw new InvalidPaymentCodeException("Invalid version: " + strPaymentCode);
            } else {
                byte[] chain = new byte[32];
                byte[] pub = new byte[33];
                // type:
                byteBuffer.get();
                // feature:
                byteBuffer.get();
                byteBuffer.get(pub);
                byteBuffer.get(chain);

                ByteBuffer pubBytes = ByteBuffer.wrap(pub);
                int firstByte = pubBytes.get();
                return firstByte == 0x02 || firstByte == 0x03;
            }
        } catch(BufferUnderflowException | InvalidPaymentCodeException bue) {
            return false;
        }
    }

    public static PaymentCode fromString(String strPaymentCode) {
        try {
            return new PaymentCode(strPaymentCode);
        } catch(InvalidPaymentCodeException e) {
            log.error("Invalid payment code", e);
        }

        return null;
    }

    public PaymentCode copy() {
        return new PaymentCode(strPaymentCode, pubkey, chain);
    }

    public String toAbbreviatedString() {
        return strPaymentCode.substring(0, 8) + "..." + strPaymentCode.substring(strPaymentCode.length() - 3);
    }

    @Override
    public boolean equals(Object o) {
        if(this == o) {
            return true;
        }
        if(o == null || getClass() != o.getClass()) {
            return false;
        }

        PaymentCode that = (PaymentCode) o;
        return strPaymentCode.equals(that.strPaymentCode);
    }

    @Override
    public int hashCode() {
        return strPaymentCode.hashCode();
    }
}

