package com.craigraw.drongo.protocol;

import com.craigraw.drongo.Utils;
import com.craigraw.drongo.address.Address;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static com.craigraw.drongo.Utils.uint32ToByteStreamLE;

public class Transaction extends TransactionPart {
    private long version;
    private long lockTime;

    private Sha256Hash cachedTxId;
    private Sha256Hash cachedWTxId;

    private ArrayList<TransactionInput> inputs;
    private ArrayList<TransactionOutput> outputs;

    public Transaction(byte[] rawtx) {
        super(rawtx, 0);
    }

    public long getVersion() {
        return version;
    }

    public long getLockTime() {
        return lockTime;
    }

    public Sha256Hash getTxId() {
        if (cachedTxId == null) {
            if (!hasWitnesses() && cachedWTxId != null) {
                cachedTxId = cachedWTxId;
            } else {
                ByteArrayOutputStream stream = new UnsafeByteArrayOutputStream(length < 32 ? 32 : length + 32);
                try {
                    bitcoinSerializeToStream(stream, false);
                } catch (IOException e) {
                    throw new RuntimeException(e); // cannot happen
                }
                cachedTxId = Sha256Hash.wrapReversed(Sha256Hash.hashTwice(stream.toByteArray()));
            }
        }
        return cachedTxId;
    }

    public Sha256Hash getWTxId() {
        if (cachedWTxId == null) {
            if (!hasWitnesses() && cachedTxId != null) {
                cachedWTxId = cachedTxId;
            } else {
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                try {
                    bitcoinSerializeToStream(baos, hasWitnesses());
                } catch (IOException e) {
                    throw new RuntimeException(e); // cannot happen
                }
                cachedWTxId = Sha256Hash.wrapReversed(Sha256Hash.hashTwice(baos.toByteArray()));
            }
        }
        return cachedWTxId;
    }

    public boolean hasWitnesses() {
        for (TransactionInput in : inputs)
            if (in.hasWitness())
                return true;
        return false;
    }

    protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        boolean useSegwit = hasWitnesses();
        bitcoinSerializeToStream(stream, useSegwit);
    }

    /**
     * Serialize according to <a href="https://github.com/bitcoin/bips/blob/master/bip-0144.mediawiki">BIP144</a> or the
     * <a href="https://en.bitcoin.it/wiki/Protocol_documentation#tx">classic format</a>, depending on if segwit is
     * desired.
     */
    protected void bitcoinSerializeToStream(OutputStream stream, boolean useSegwit) throws IOException {
        // version
        uint32ToByteStreamLE(version, stream);
        // marker, flag
        if (useSegwit) {
            stream.write(0);
            stream.write(1);
        }
        // txin_count, txins
        stream.write(new VarInt(inputs.size()).encode());
        for (TransactionInput in : inputs)
            in.bitcoinSerialize(stream);
        // txout_count, txouts
        stream.write(new VarInt(outputs.size()).encode());
        for (TransactionOutput out : outputs)
            out.bitcoinSerialize(stream);
        // script_witnisses
        if (useSegwit) {
            for (TransactionInput in : inputs) {
                in.getWitness().bitcoinSerializeToStream(stream);
            }
        }
        // lock_time
        uint32ToByteStreamLE(lockTime, stream);
    }

    /**
     * Deserialize according to <a href="https://github.com/bitcoin/bips/blob/master/bip-0144.mediawiki">BIP144</a> or
     * the <a href="https://en.bitcoin.it/wiki/Protocol_documentation#tx">classic format</a>, depending on if the
     * transaction is segwit or not.
     */
    public void parse() {
        // version
        version = readUint32();
        // peek at marker
        byte marker = rawtx[cursor];
        boolean useSegwit = marker == 0;
        // marker, flag
        if (useSegwit) {
            readBytes(2);
        }
        // txin_count, txins
        parseInputs();
        // txout_count, txouts
        parseOutputs();
        // script_witnesses
        if (useSegwit)
            parseWitnesses();
        // lock_time
        lockTime = readUint32();

        length = cursor - offset;
    }

    private void parseInputs() {
        long numInputs = readVarInt();
        inputs = new ArrayList<>(Math.min((int) numInputs, Utils.MAX_INITIAL_ARRAY_LENGTH));
        for (long i = 0; i < numInputs; i++) {
            TransactionInput input = new TransactionInput(this, rawtx, cursor);
            inputs.add(input);
            long scriptLen = readVarInt(TransactionOutPoint.MESSAGE_LENGTH);
            cursor += scriptLen + 4;
        }
    }

    private void parseOutputs() {
        long numOutputs = readVarInt();
        outputs = new ArrayList<>(Math.min((int) numOutputs, Utils.MAX_INITIAL_ARRAY_LENGTH));
        for (long i = 0; i < numOutputs; i++) {
            TransactionOutput output = new TransactionOutput(this, rawtx, cursor);
            outputs.add(output);
            long scriptLen = readVarInt(8);
            cursor += scriptLen;
        }
    }

    private void parseWitnesses() {
        int numWitnesses = inputs.size();
        for (int i = 0; i < numWitnesses; i++) {
            long pushCount = readVarInt();
            TransactionWitness witness = new TransactionWitness((int) pushCount);
            inputs.get(i).setWitness(witness);
            for (int y = 0; y < pushCount; y++) {
                long pushSize = readVarInt();
                byte[] push = readBytes((int) pushSize);
                witness.setPush(y, push);
            }
        }
    }

    /** Returns an unmodifiable view of all inputs. */
    public List<TransactionInput> getInputs() {
        return Collections.unmodifiableList(inputs);
    }

    /** Returns an unmodifiable view of all outputs. */
    public List<TransactionOutput> getOutputs() {
        return Collections.unmodifiableList(outputs);
    }

    /**
     * These constants are a part of a scriptSig signature on the inputs. They define the details of how a
     * transaction can be redeemed, specifically, they control how the hash of the transaction is calculated.
     */
    public enum SigHash {
        ALL(1),
        NONE(2),
        SINGLE(3),
        ANYONECANPAY(0x80), // Caution: Using this type in isolation is non-standard. Treated similar to ANYONECANPAY_ALL.
        ANYONECANPAY_ALL(0x81),
        ANYONECANPAY_NONE(0x82),
        ANYONECANPAY_SINGLE(0x83),
        UNSET(0); // Caution: Using this type in isolation is non-standard. Treated similar to ALL.

        public final int value;

        /**
         * @param value
         */
        private SigHash(final int value) {
            this.value = value;
        }

        /**
         * @return the value as a int
         */
        public int intValue() {
            return this.value;
        }

        /**
         * @return the value as a byte
         */
        public byte byteValue() {
            return (byte) this.value;
        }

        public static SigHash fromInt(int sigHashInt) {
            for(SigHash value : SigHash.values()) {
                if(sigHashInt == value.intValue()) {
                    return value;
                }
            }

            throw new IllegalArgumentException("No defined sighash value for int " + sigHashInt);
        }
    }

    public static final void main(String[] args) {
        String hex = "020000000001017811567adbc80d903030ae30fc28d5cd7c395a6a74ccab96734cf5da5bd67f1a0100000000feffffff0227030000000000002200206a4c4d9be3de0e40f601d11cebd86b6d8763caa9d91f8e5e8de5f5fc8657d46da00f000000000000220020e9eaae21539323a2627701dd2c234e3499e0faf563d73fd5fcd4d263192924a604004730440220385a8b9b998abfc9319b710c44b78727b189d7029fc6e4b6c4013a3ff2976a7b02207ab7ca6aedd8d86de6d08835d8b3e4481c778043675f59f72241e7d608aa80820147304402201f62ed94f41b77ee5eb490e127ead10bd4c2144a2eacc8d61865d86fec437ed2022037488b5b96390911ded8ba086b419c335c037dc4cb004202313635741d3691b001475221022a0d4dd0d1a7182cd45de3f460737988c17653428dcb32d9c2ab35a584c716882103171d9b824205cd5db6e9353676a292ca954b24d8310a36fc983469ba3fb507a252ae8d0b0900";
        byte[] transactionBytes = Utils.hexToBytes(hex);
        Transaction transaction = new Transaction(transactionBytes);

        Address[] addresses = transaction.getOutputs().get(0).getScript().getToAddresses();
        System.out.println(addresses[0]);
    }
}
