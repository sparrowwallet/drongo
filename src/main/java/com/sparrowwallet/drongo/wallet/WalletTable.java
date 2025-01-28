package com.sparrowwallet.drongo.wallet;

public class WalletTable extends Persistable {
    private final TableType tableType;
    private final Double[] widths;

    public WalletTable(TableType tableType, Double[] widths) {
        this.tableType = tableType;
        this.widths = widths;
    }

    public TableType getTableType() {
        return tableType;
    }

    public Double[] getWidths() {
        return widths;
    }

    @Override
    public final boolean equals(Object o) {
        if(this == o) {
            return true;
        }
        if(!(o instanceof WalletTable that)) {
            return false;
        }

        return tableType == that.tableType;
    }

    @Override
    public int hashCode() {
        return tableType.hashCode();
    }
}
