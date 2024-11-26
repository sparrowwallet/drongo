package com.sparrowwallet.drongo;

public enum OsType {
    WINDOWS("Windows"),
    MACOS("macOS"),
    UNIX("Unix"),
    UNKNOWN("");

    private static final OsType current = getCurrentPlatform();
    private final String platformId;

    OsType(String platformId) {
        this.platformId = platformId;
    }

    /**
     * Returns platform id. Usually used to specify platform dependent styles
     *
     * @return platform id
     */
    public String getPlatformId() {
        return platformId;
    }

    /**
     * @return the current OS.
     */
    public static OsType getCurrent() {
        return current;
    }

    private static OsType getCurrentPlatform() {
        String osName = System.getProperty("os.name");
        if(osName.startsWith("Windows")) {
            return WINDOWS;
        }
        if(osName.startsWith("Mac")) {
            return MACOS;
        }
        if(osName.startsWith("SunOS")) {
            return UNIX;
        }
        if(osName.startsWith("Linux")) {
            return UNIX;
        }
        return UNKNOWN;
    }
}
