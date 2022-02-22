package com.sparrowwallet.drongo;

import com.sparrowwallet.drongo.crypto.ChildNumber;

import java.util.List;

public enum KeyPurpose {
    RECEIVE(ChildNumber.ZERO), CHANGE(ChildNumber.ONE);

    public static final List<KeyPurpose> DEFAULT_PURPOSES = List.of(RECEIVE, CHANGE);

    //The receive derivation is also used for BIP47 notifications
    public static final KeyPurpose NOTIFICATION = RECEIVE;
    //The change derivation is reused for the send chain in BIP47 wallets
    public static final KeyPurpose SEND = CHANGE;

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
