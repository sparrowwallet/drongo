package com.sparrowwallet.drongo;

import com.sparrowwallet.drongo.protocol.Transaction;

public enum BitcoinUnit {
    AUTO("Auto") {
        @Override
        public long getSatsValue(double unitValue) {
            throw new UnsupportedOperationException("Auto unit cannot convert bitcoin values");
        }

        @Override
        public double getValue(long satsValue) {
            throw new UnsupportedOperationException("Auto unit cannot convert bitcoin values");
        }
    },
    BTC("BTC") {
        @Override
        public long getSatsValue(double unitValue) {
            return Math.round(unitValue * Transaction.SATOSHIS_PER_BITCOIN);
        }

        @Override
        public double getValue(long satsValue) {
            return (double)satsValue / Transaction.SATOSHIS_PER_BITCOIN;
        }
    },
    SATOSHIS("sats") {
        @Override
        public long getSatsValue(double unitValue) {
            return (long)unitValue;
        }

        @Override
        public double getValue(long satsValue) {
            return (double)satsValue;
        }
    };

    private final String label;

    BitcoinUnit(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }

    public abstract long getSatsValue(double unitValue);

    public abstract double getValue(long satsValue);

    public double convertFrom(double fromValue, BitcoinUnit fromUnit) {
        long satsValue = fromUnit.getSatsValue(fromValue);
        return getValue(satsValue);
    }

    public static long getAutoThreshold() {
        return 100000000L;
    }

    @Override
    public String toString() {
        return label;
    }
}
