package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.crypto.ChildNumber;
import com.sparrowwallet.drongo.protocol.ScriptType;

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
    ACCOUNT_10("Account #10", new ChildNumber(10, true)),
    ACCOUNT_11("Account #11", new ChildNumber(11, true)),
    ACCOUNT_12("Account #12", new ChildNumber(12, true)),
    ACCOUNT_13("Account #13", new ChildNumber(13, true)),
    ACCOUNT_14("Account #14", new ChildNumber(14, true)),
    ACCOUNT_15("Account #15", new ChildNumber(15, true)),
    ACCOUNT_16("Account #16", new ChildNumber(16, true)),
    ACCOUNT_17("Account #17", new ChildNumber(17, true)),
    ACCOUNT_18("Account #18", new ChildNumber(18, true)),
    ACCOUNT_19("Account #19", new ChildNumber(19, true)),
    ACCOUNT_20("Account #20", new ChildNumber(20, true)),
    ACCOUNT_21("Account #21", new ChildNumber(21, true)),
    ACCOUNT_22("Account #22", new ChildNumber(22, true)),
    ACCOUNT_23("Account #23", new ChildNumber(23, true)),
    ACCOUNT_24("Account #24", new ChildNumber(24, true)),
    ACCOUNT_25("Account #25", new ChildNumber(25, true)),
    ACCOUNT_26("Account #26", new ChildNumber(26, true)),
    ACCOUNT_27("Account #27", new ChildNumber(27, true)),
    ACCOUNT_28("Account #28", new ChildNumber(28, true)),
    ACCOUNT_29("Account #29", new ChildNumber(29, true)),
    ACCOUNT_30("Account #30", new ChildNumber(30, true)),
    WHIRLPOOL_PREMIX("Premix", new ChildNumber(2147483645, true), ScriptType.P2WPKH, null),
    WHIRLPOOL_POSTMIX("Postmix", new ChildNumber(2147483646, true), ScriptType.P2WPKH, Wallet.DEFAULT_LOOKAHEAD * 2),
    WHIRLPOOL_BADBANK("Badbank", new ChildNumber(2147483644, true), ScriptType.P2WPKH, null);

    public static final List<StandardAccount> DISCOVERY_ACCOUNTS = List.of(ACCOUNT_0, ACCOUNT_1, ACCOUNT_2, ACCOUNT_3, ACCOUNT_4, ACCOUNT_5, ACCOUNT_6, ACCOUNT_7, ACCOUNT_8, ACCOUNT_9, WHIRLPOOL_PREMIX, WHIRLPOOL_POSTMIX, WHIRLPOOL_BADBANK);
    public static final List<StandardAccount> MIXABLE_ACCOUNTS = List.of(ACCOUNT_0, WHIRLPOOL_POSTMIX, WHIRLPOOL_BADBANK);
    public static final List<StandardAccount> WHIRLPOOL_ACCOUNTS = List.of(WHIRLPOOL_PREMIX, WHIRLPOOL_POSTMIX, WHIRLPOOL_BADBANK);
    public static final List<StandardAccount> WHIRLPOOL_MIX_ACCOUNTS = List.of(WHIRLPOOL_PREMIX, WHIRLPOOL_POSTMIX);

    StandardAccount(String name, ChildNumber childNumber) {
        this.name = name;
        this.childNumber = childNumber;
        this.requiredScriptType = null;
        this.minimumGapLimit = null;
    }

    StandardAccount(String name, ChildNumber childNumber, ScriptType requiredScriptType, Integer minimumGapLimit) {
        this.name = name;
        this.childNumber = childNumber;
        this.requiredScriptType = requiredScriptType;
        this.minimumGapLimit = minimumGapLimit;
    }

    private final String name;
    private final ChildNumber childNumber;
    private final ScriptType requiredScriptType;
    private final Integer minimumGapLimit;

    public String getName() {
        return name;
    }

    public ChildNumber getChildNumber() {
        return childNumber;
    }

    public int getAccountNumber() {
        return childNumber.num();
    }

    public ScriptType getRequiredScriptType() {
        return requiredScriptType;
    }

    public Integer getMinimumGapLimit() {
        return minimumGapLimit;
    }

    @Override
    public String toString() {
        return name;
    }

    public static boolean isMixableAccount(StandardAccount standardAccount) {
        return standardAccount != null && MIXABLE_ACCOUNTS.contains(standardAccount);
    }

    public static boolean isWhirlpoolAccount(StandardAccount standardAccount) {
        return standardAccount != null && WHIRLPOOL_ACCOUNTS.contains(standardAccount);
    }

    public static boolean isWhirlpoolMixAccount(StandardAccount standardAccount) {
        return standardAccount != null && WHIRLPOOL_MIX_ACCOUNTS.contains(standardAccount);
    }
}
