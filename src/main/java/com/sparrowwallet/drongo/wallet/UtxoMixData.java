package com.sparrowwallet.drongo.wallet;

public class UtxoMixData extends Persistable {
    private final String poolId;
    private final int mixesDone;
    private final Long forwarding;

    public UtxoMixData(String poolId, int mixesDone, Long forwarding) {
        this.poolId = poolId;
        this.mixesDone = mixesDone;
        this.forwarding = forwarding;
    }

    public String getPoolId() {
        return poolId;
    }

    public int getMixesDone() {
        return mixesDone;
    }

    public Long getForwarding() {
        return forwarding;
    }

    @Override
    public String toString() {
        return "{poolId:" + poolId + ", mixesDone:" + mixesDone + ", forwarding:" + forwarding + "}";
    }
}
