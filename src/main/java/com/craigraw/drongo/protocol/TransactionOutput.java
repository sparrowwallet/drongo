package com.craigraw.drongo.protocol;

import com.craigraw.drongo.Utils;
import com.craigraw.drongo.address.Address;

import java.io.IOException;
import java.io.OutputStream;

public class TransactionOutput extends TransactionPart {
    // The output's value is kept as a native type in order to save class instances.
    private long value;

    // A transaction output has a script used for authenticating that the redeemer is allowed to spend
    // this output.
    private byte[] scriptBytes;

    private Script script;

    private int scriptLen;

    private Address[] addresses;

    public TransactionOutput(Transaction transaction, byte[] rawtx, int offset) {
        super(rawtx, offset);
        setParent(transaction);
    }

    protected void parse() throws ProtocolException {
        value = readInt64();
        scriptLen = (int) readVarInt();
        length = cursor - offset + scriptLen;
        scriptBytes = readBytes(scriptLen);
    }

    protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        Utils.int64ToByteStreamLE(value, stream);
        // TODO: Move script serialization into the Script class, where it belongs.
        stream.write(new VarInt(scriptBytes.length).encode());
        stream.write(scriptBytes);
    }

    public byte[] getScriptBytes() {
        return scriptBytes;
    }

    public Script getScript() {
        if(script == null) {
            script = new Script(scriptBytes);
        }

        return script;
    }

    public long getValue() {
        return value;
    }

    public Address[] getAddresses() {
        return addresses;
    }

    public void setAddresses(Address[] addresses) {
        this.addresses = addresses;
    }
}
