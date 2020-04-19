package com.sparrowwallet.drongo;

import com.sparrowwallet.drongo.crypto.ChildNumber;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class KeyDerivation {
    private final String masterFingerprint;
    private final String derivationPath;
    private final transient List<ChildNumber> derivation;

    public KeyDerivation(String masterFingerprint, String derivationPath) {
        this.masterFingerprint = masterFingerprint;
        this.derivationPath = derivationPath;
        this.derivation = parsePath(derivationPath);
    }

    public String getMasterFingerprint() {
        return masterFingerprint;
    }

    public String getDerivationPath() {
        return derivationPath;
    }

    public List<ChildNumber> getDerivation() {
        return Collections.unmodifiableList(derivation);
    }

    public static List<ChildNumber> parsePath(String path) {
        return parsePath(path, 0);
    }

    public static List<ChildNumber> parsePath(String path, int wildcardReplacement) {
        List<ChildNumber> nodes = new ArrayList<>();
        if(path == null) {
            return nodes;
        }

        String[] parsedNodes = path.replace("M", "").replace("m", "").split("/");
        for (String n : parsedNodes) {
            n = n.replaceAll(" ", "");
            if (n.length() == 0) continue;
            boolean isHard = n.endsWith("H") || n.endsWith("h") || n.endsWith("'");
            if (isHard) n = n.substring(0, n.length() - 1);
            if (n.equals("*")) n = Integer.toString(wildcardReplacement);
            int nodeNumber = Integer.parseInt(n);
            nodes.add(new ChildNumber(nodeNumber, isHard));
        }

        return nodes;
    }

    public static String writePath(List<ChildNumber> pathList) {
        String path = "m";
        for (ChildNumber child: pathList) {
            path += "/";
            path += child.toString();
        }

        return path;
    }

    public static boolean isValid(String derivationPath) {
        try {
            parsePath(derivationPath);
        } catch (Exception e) {
            return false;
        }

        return true;
    }

    public KeyDerivation copy() {
        return new KeyDerivation(masterFingerprint, derivationPath);
    }

    public String toString() {
        return masterFingerprint + (derivationPath != null ? derivationPath.replace("m", "") : "");
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        KeyDerivation that = (KeyDerivation) o;
        return that.toString().equals(this.toString());
    }

    @Override
    public int hashCode() {
        return toString().hashCode();
    }
}
