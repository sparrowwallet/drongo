package com.sparrowwallet.drongo;

import ch.qos.logback.core.PropertyDefinerBase;

public class PropertyDefiner extends PropertyDefinerBase {
    private String application;

    public void setApplication(String application) {
        this.application = application;
    }

    @Override
    public String getPropertyValue() {
        return ApplicationDir.STATE.get(application).getAbsolutePath();
    }
}
