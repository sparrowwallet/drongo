package com.sparrowwallet.drongo;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;

import java.security.Provider;

public class Drongo {
    public static void setRootLogLevel(Level level) {
        ch.qos.logback.classic.Logger root = (ch.qos.logback.classic.Logger)LoggerFactory.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
        root.setLevel(ch.qos.logback.classic.Level.toLevel(level.toString()));
    }

    public static void removeRootLogAppender(String appenderName) {
        ch.qos.logback.classic.Logger root = (ch.qos.logback.classic.Logger)LoggerFactory.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
        root.detachAppender(appenderName);
    }

    public static Provider getProvider() {
        return new BouncyCastleProvider();
    }
}
