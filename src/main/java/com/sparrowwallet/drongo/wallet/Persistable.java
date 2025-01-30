package com.sparrowwallet.drongo.wallet;

public class Persistable {
    public static final int MAX_LABEL_LENGTH = 255;

    private Long id;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }
}
