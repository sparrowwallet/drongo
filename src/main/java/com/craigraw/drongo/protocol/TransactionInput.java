package com.craigraw.drongo.protocol;

import com.craigraw.drongo.Utils;

import java.io.IOException;
import java.io.OutputStream;

public class TransactionInput extends TransactionPart {
    // Allows for altering transactions after they were broadcast. Values below NO_SEQUENCE-1 mean it can be altered.
    private long sequence;

    // Data needed to connect to the output of the transaction we're gathering coins from.
    private TransactionOutPoint outpoint;

    private byte[] scriptBytes;

    private Script scriptSig;

    private TransactionWitness witness;

    public TransactionInput(Transaction transaction, byte[] rawtx, int offset) {
        super(rawtx, offset);
        setParent(transaction);
    }

    protected void parse() throws ProtocolException {
        outpoint = new TransactionOutPoint(rawtx, cursor, this);
        cursor += outpoint.getMessageSize();
        int scriptLen = (int) readVarInt();
        length = cursor - offset + scriptLen + 4;
        scriptBytes = readBytes(scriptLen);
        sequence = readUint32();
    }

    public byte[] getScriptBytes() {
        return scriptBytes;
    }

    public Script getScriptSig() {
        if(scriptSig == null) {
            scriptSig = new Script(scriptBytes);
        }

        return scriptSig;
    }

    void setScriptBytes(byte[] scriptBytes) {
        super.rawtx = null;
        this.scriptSig = null;
        int oldLength = length;
        this.scriptBytes = scriptBytes;
        // 40 = previous_outpoint (36) + sequence (4)
        int newLength = 40 + (scriptBytes == null ? 1 : VarInt.sizeOf(scriptBytes.length) + scriptBytes.length);
        adjustLength(newLength - oldLength);
    }

    public void clearScriptBytes() {
        setScriptBytes(new byte[0]);
    }

    public TransactionWitness getWitness() {
        return witness != null ? witness : TransactionWitness.EMPTY;
    }

    public void setWitness(TransactionWitness witness) {
        this.witness = witness;
    }

    public boolean hasWitness() {
        return witness != null && witness.getPushCount() != 0;
    }

    public TransactionOutPoint getOutpoint() {
        return outpoint;
    }

    public long getSequenceNumber() {
        return sequence;
    }

    public void setSequenceNumber(long sequence) {
        this.sequence = sequence;
    }

    /**
     * Coinbase transactions have special inputs with hashes of zero. If this is such an input, returns true.
     */
    public boolean isCoinBase() {
        return outpoint.getHash().equals(Sha256Hash.ZERO_HASH) &&
                (outpoint.getIndex() & 0xFFFFFFFFL) == 0xFFFFFFFFL;  // -1 but all is serialized to the wire as unsigned int.
    }

    protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        outpoint.bitcoinSerializeToStream(stream);
        stream.write(new VarInt(scriptBytes.length).encode());
        stream.write(scriptBytes);
        Utils.uint32ToByteStreamLE(sequence, stream);
    }
}
