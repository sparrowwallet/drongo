package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.address.Address;

public class Payment {
    private Address address;
    private String label;
    private long amount;
    private boolean sendMax;
    private Type type;

    public Payment(Address address, String label, long amount, boolean sendMax) {
        this(address, label, amount, sendMax, Type.DEFAULT);
    }

    public Payment(Address address, String label, long amount, boolean sendMax, Type type) {
        this.address = address;
        this.label = label;
        this.amount = amount;
        this.sendMax = sendMax;
        this.type = type;
    }

    public Address getAddress() {
        return address;
    }

    public void setAddress(Address address) {
        this.address = address;
    }

    public String getLabel() {
        return label;
    }

    public void setLabel(String label) {
        this.label = label;
    }

    public long getAmount() {
        return amount;
    }

    public void setAmount(long amount) {
        this.amount = amount;
    }

    public boolean isSendMax() {
        return sendMax;
    }

    public void setSendMax(boolean sendMax) {
        this.sendMax = sendMax;
    }

    public Type getType() {
        return type;
    }

    public void setType(Type type) {
        this.type = type;
    }

    public enum Type {
        DEFAULT, WHIRLPOOL_FEE, FAKE_MIX, MIX;
    }
}
