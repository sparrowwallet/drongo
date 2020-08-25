package com.sparrowwallet.drongo;

import ch.qos.logback.core.PropertyDefinerBase;

public class PropertyDefiner extends PropertyDefinerBase {
    private String application;

    public void setApplication(String application) {
        this.application = application;
    }

    @Override
    public String getPropertyValue() {
        return isWindows() ? System.getenv("APPDATA") + "/" + application.substring(0, 1).toUpperCase() + application.substring(1).toLowerCase() : System.getProperty("user.home") + "/." + application.toLowerCase();
    }

    private boolean isWindows() {
        String osName = System.getProperty("os.name");
        return (osName != null && osName.toLowerCase().startsWith("windows"));
    }
}
