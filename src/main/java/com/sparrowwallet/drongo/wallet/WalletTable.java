package com.sparrowwallet.drongo.wallet;

public class WalletTable extends Persistable {
    private final TableType tableType;
    private final Double[] widths;
    private final int sortColumn;
    private final SortDirection sortDirection;

    public WalletTable(TableType tableType, Double[] widths, int sortColumn, SortDirection sortDirection) {
        this.tableType = tableType;
        this.widths = widths;
        this.sortColumn = sortColumn;
        this.sortDirection = sortDirection;
    }

    public WalletTable(TableType tableType, Double[] widths, Sort sort) {
        this.tableType = tableType;
        this.widths = widths;
        this.sortColumn = sort.sortColumn;
        this.sortDirection = sort.sortDirection;
    }

    public TableType getTableType() {
        return tableType;
    }

    public Double[] getWidths() {
        return widths;
    }

    public int getSortColumn() {
        return sortColumn;
    }

    public SortDirection getSortDirection() {
        return sortDirection;
    }

    public Sort getSort() {
        return new Sort(sortColumn, sortDirection);
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

    public record Sort(int sortColumn, SortDirection sortDirection) {}
}
