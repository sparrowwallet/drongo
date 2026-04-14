package com.sparrowwallet.drongo.policy;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Miniscript {
    private static final Pattern KEYHASH_PATTERN = Pattern.compile("pkh?\\(");
    private static final Pattern TAPROOT_PATTERN = Pattern.compile("tr\\(");
    private static final Pattern SILENT_PAYMENTS_PATTERN = Pattern.compile("sp\\(");
    private static final Pattern MULTI_PATTERN = Pattern.compile("multi\\((\\d+)");

    private String script;

    public Miniscript(String script) {
        this.script = script;
    }

    public String getScript() {
        return script;
    }

    public void setScript(String script) {
        this.script = script;
    }

    public int getNumSignaturesRequired() {
        Matcher singleMatcher = KEYHASH_PATTERN.matcher(script);
        if(singleMatcher.find()) {
            return 1;
        }

        Matcher taprootMatcher = TAPROOT_PATTERN.matcher(script);
        if(taprootMatcher.find()) {
            return 1;
        }

        Matcher silentPaymentsMatcher = SILENT_PAYMENTS_PATTERN.matcher(script);
        if(silentPaymentsMatcher.find()) {
            return 1;
        }

        Matcher multiMatcher = MULTI_PATTERN.matcher(script);
        if(multiMatcher.find()) {
            String threshold = multiMatcher.group(1);
            return Integer.parseInt(threshold);
        } else {
            throw new IllegalArgumentException("Could not find multisig threshold in " + this);
        }
    }

    public Miniscript copy() {
        return new Miniscript(script);
    }

    @Override
    public String toString() {
        return getScript();
    }
}
