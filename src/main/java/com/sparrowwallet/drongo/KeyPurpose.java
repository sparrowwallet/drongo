package com.sparrowwallet.drongo;

import com.sparrowwallet.drongo.crypto.ChildNumber;

import java.util.List;

public enum KeyPurpose {
    RECEIVE(ChildNumber.ZERO), CHANGE(ChildNumber.ONE);

    public static final List<KeyPurpose> DEFAULT_PURPOSES = List.of(RECEIVE, CHANGE);

    private final ChildNumber pathIndex;

    KeyPurpose(ChildNumber pathIndex) {
        this.pathIndex = pathIndex;
    }

    public ChildNumber getPathIndex() {
        return pathIndex;
    }

    public static KeyPurpose fromChildNumber(ChildNumber childNumber) {
        for(KeyPurpose keyPurpose : values()) {
            if(keyPurpose.getPathIndex().equals(childNumber)) {
                return keyPurpose;
            }
        }

        return null;
    }
}
