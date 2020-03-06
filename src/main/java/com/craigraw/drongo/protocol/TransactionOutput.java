package com.craigraw.drongo.protocol;

import com.craigraw.drongo.Utils;
import com.craigraw.drongo.address.Address;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class TransactionOutput extends TransactionPart {
    // The output's value is kept as a native type in order to save class instances.
    private long value;

    // A transaction output has a script used for authenticating that the redeemer is allowed to spend
    // this output.
    private byte[] scriptBytes;

    private Script script;

    private Address[] addresses = new Address[0];

    public TransactionOutput(Transaction parent, byte[] rawtx, int offset) {
        super(rawtx, offset);
        setParent(parent);
    }

    public TransactionOutput(Transaction parent, long value, byte[] scriptBytes) {
        super(new byte[0], 0);
        this.value = value;
        this.scriptBytes = scriptBytes;
        setParent(parent);
        length = 8 + VarInt.sizeOf(scriptBytes.length) + scriptBytes.length;

        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            bitcoinSerializeToStream(baos);
            rawtx = baos.toByteArray();
        } catch(IOException e) {
            //ignore
        }
    }

    protected void parse() throws ProtocolException {
        value = readInt64();
        int scriptLen = (int) readVarInt();
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
