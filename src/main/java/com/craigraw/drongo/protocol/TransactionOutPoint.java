package com.craigraw.drongo.protocol;

import com.craigraw.drongo.address.Address;

public class TransactionOutPoint extends TransactionPart {

    static final int MESSAGE_LENGTH = 36;

    /** Hash of the transaction to which we refer. */
    private Sha256Hash hash;
    /** Which output of that transaction we are talking about. */
    private long index;

    private Address[] addresses = new Address[0];

    public TransactionOutPoint(byte[] rawtx, int offset, TransactionPart parent) {
        super(rawtx, offset);
        setParent(parent);
    }

    protected void parse() throws ProtocolException {
        length = MESSAGE_LENGTH;
        hash = readHash();
        index = readUint32();
    }

    public Sha256Hash getHash() {
        return hash;
    }

    public long getIndex() {
        return index;
    }

    public Address[] getAddresses() {
        return addresses;
    }

    public void setAddresses(Address[] addresses) {
        this.addresses = addresses;
    }
}
