package com.sparrowwallet.drongo;

import org.slf4j.event.Level;

public interface LogHandler {
    void handleLog(String threadName, Level level, String message, String loggerName, long timestamp, StackTraceElement[] callerData);
}
