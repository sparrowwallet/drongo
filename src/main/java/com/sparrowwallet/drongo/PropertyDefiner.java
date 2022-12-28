package com.sparrowwallet.drongo;

import ch.qos.logback.core.PropertyDefinerBase;

import java.util.Locale;

public class PropertyDefiner extends PropertyDefinerBase {
    private String application;

    public void setApplication(String application) {
        this.application = application;
    }

    @Override
    public String getPropertyValue() {
        if(System.getProperty(application.toLowerCase(Locale.ROOT) + ".home") != null) {
            return System.getProperty(application.toLowerCase(Locale.ROOT) + ".home");
        }

        return isWindows() ? System.getenv("APPDATA") + "/" + application.substring(0, 1).toUpperCase(Locale.ROOT) + application.substring(1).toLowerCase(Locale.ROOT) : System.getProperty("user.home") + "/." + application.toLowerCase(Locale.ROOT);
    }

    private boolean isWindows() {
        String osName = System.getProperty("os.name");
        return (osName != null && osName.toLowerCase(Locale.ROOT).startsWith("windows"));
    }
}
