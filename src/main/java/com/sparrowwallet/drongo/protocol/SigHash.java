package com.sparrowwallet.drongo.protocol;

/**
 * These constants are a part of a scriptSig signature on the inputs. They define the details of how a
 * transaction can be redeemed, specifically, they control how the hash of the transaction is calculated.
 */
public enum SigHash {
    ALL("All (Recommended)", (byte)1),
    NONE("None", (byte)2),
    SINGLE("Single", (byte)3),
    ANYONECANPAY("Anyone Can Pay", (byte)0x80), // Caution: Using this type in isolation is non-standard. Treated similar to ANYONECANPAY_ALL.
    ANYONECANPAY_ALL("All + Anyone Can Pay", (byte)0x81),
    ANYONECANPAY_NONE("None + Anyone Can Pay", (byte)0x82),
    ANYONECANPAY_SINGLE("Single + Anyone Can Pay", (byte)0x83),
    UNSET("Unset", (byte)0); // Caution: Using this type in isolation is non-standard. Treated similar to ALL.

    private final String name;
    public final byte value;

    private SigHash(final String name, final byte value) {
        this.name = name;
        this.value = value;
    }

    public String getName() {
        return name;
    }

    /**
     * @return the value as a byte
     */
    public byte byteValue() {
        return this.value;
    }

    public int intValue() {
        return Byte.toUnsignedInt(value);
    }

    public boolean anyoneCanPay() {
        return (value & SigHash.ANYONECANPAY.value) != 0;
    }

    public static SigHash fromByte(byte sigHashByte) {
        for(SigHash value : SigHash.values()) {
            if(sigHashByte == value.byteValue()) {
                return value;
            }
        }

        throw new IllegalArgumentException("No defined sighash value for byte " + sigHashByte);
    }

    @Override
    public String toString() {
        return getName();
    }
}
