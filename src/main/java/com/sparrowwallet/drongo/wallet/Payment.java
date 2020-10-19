package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.address.Address;

public class Payment {
    private Address address;
    private String label;
    private long amount;
    private boolean sendMax;

    public Payment(Address address, String label, long amount, boolean sendMax) {
        this.address = address;
        this.label = label;
        this.amount = amount;
        this.sendMax = sendMax;
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
}
