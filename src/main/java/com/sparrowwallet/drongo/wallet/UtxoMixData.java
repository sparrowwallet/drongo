package com.sparrowwallet.drongo.wallet;

public class UtxoMixData extends Persistable {
    private final int mixesDone;
    private final Long expired;

    public UtxoMixData(int mixesDone, Long expired) {
        this.mixesDone = mixesDone;
        this.expired = expired;
    }

    public int getMixesDone() {
        return mixesDone;
    }

    public Long getExpired() {
        return expired;
    }

    @Override
    public String toString() {
        return "{mixesDone:" + mixesDone + ", expired: " + expired + "}";
    }
}
