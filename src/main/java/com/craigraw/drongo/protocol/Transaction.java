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

    public static final void main(String[] args) {
        String hex = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704f4a3051c0152ffffffff0100f2052a0100000043410485e646ba748709356dfbb75465563fc7954d547fd5bd9c69f66e991c61e533fc876b74e0e638a5ba22ea94111fa4795a4a184b8cdf24e88b24787d1a24061795ac00000000";
        byte[] transactionBytes = Utils.hexToBytes(hex);
        Transaction transaction = new Transaction(transactionBytes);

        Address[] addresses = transaction.getOutputs().get(0).getScript().getToAddresses();
        System.out.println(addresses[0]);
    }
}
