package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.crypto.ChildNumber;

import java.util.List;

public enum StandardAccount {
    ACCOUNT_0("Account #0", new ChildNumber(0, true)),
    ACCOUNT_1("Account #1", new ChildNumber(1, true)),
    ACCOUNT_2("Account #2", new ChildNumber(2, true)),
    ACCOUNT_3("Account #3", new ChildNumber(3, true)),
    ACCOUNT_4("Account #4", new ChildNumber(4, true)),
    ACCOUNT_5("Account #5", new ChildNumber(5, true)),
    ACCOUNT_6("Account #6", new ChildNumber(6, true)),
    ACCOUNT_7("Account #7", new ChildNumber(7, true)),
    ACCOUNT_8("Account #8", new ChildNumber(8, true)),
    ACCOUNT_9("Account #9", new ChildNumber(9, true)),
    WHIRLPOOL_PREMIX("Premix", new ChildNumber(2147483645, true)),
    WHIRLPOOL_POSTMIX("Postmix", new ChildNumber(2147483646, true)),
    WHIRLPOOL_BADBANK("Badbank", new ChildNumber(2147483644, true));

    public static final List<StandardAccount> WHIRLPOOL_ACCOUNTS = List.of(WHIRLPOOL_PREMIX, WHIRLPOOL_POSTMIX, WHIRLPOOL_BADBANK);

    StandardAccount(String name, ChildNumber childNumber) {
        this.name = name;
        this.childNumber = childNumber;
    }

    private final String name;
    private final ChildNumber childNumber;

    public String getName() {
        return name;
    }

    public ChildNumber getChildNumber() {
        return childNumber;
    }

    public int getAccountNumber() {
        return childNumber.num();
    }

    @Override
    public String toString() {
        return name;
    }
}
