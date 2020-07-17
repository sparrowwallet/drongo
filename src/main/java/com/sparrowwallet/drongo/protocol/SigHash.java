package com.sparrowwallet.drongo.protocol;

/**
 * These constants are a part of a scriptSig signature on the inputs. They define the details of how a
 * transaction can be redeemed, specifically, they control how the hash of the transaction is calculated.
 */
public enum SigHash {
    ALL("All (Recommended)", 1),
    NONE("None", 2),
    SINGLE("Single", 3),
    ANYONECANPAY("Anyone Can Pay", 0x80), // Caution: Using this type in isolation is non-standard. Treated similar to ANYONECANPAY_ALL.
    ANYONECANPAY_ALL("All + Anyone Can Pay", 0x81),
    ANYONECANPAY_NONE("None + Anyone Can Pay", 0x82),
    ANYONECANPAY_SINGLE("Single + Anyone Can Pay", 0x83),
    UNSET("Unset", 0); // Caution: Using this type in isolation is non-standard. Treated similar to ALL.

    private final String name;
    public final int value;

    /**
     * @param value
     */
    private SigHash(final String name, final int value) {
        this.name = name;
        this.value = value;
    }

    public String getName() {
        return name;
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

    @Override
    public String toString() {
        return getName();
    }
}
