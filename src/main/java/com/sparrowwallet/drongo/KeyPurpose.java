package com.sparrowwallet.drongo;

public enum KeyPurpose {
    RECEIVE(0), CHANGE(1);

    private final int pathIndex;

    KeyPurpose(int pathIndex) {
        this.pathIndex = pathIndex;
    }

    public int getPathIndex() {
        return pathIndex;
    }
}
