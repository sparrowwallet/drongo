package com.sparrowwallet.drongo;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.AppenderBase;
import org.slf4j.event.Level;

import java.lang.reflect.InvocationTargetException;

public class ApplicationAppender extends AppenderBase<ILoggingEvent> {
    private LogHandler callback;

    @Override
    protected void append(ILoggingEvent e) {
        callback.handleLog(e.getThreadName(), Level.valueOf(e.getLevel().toString()), e.getMessage(), e.getLoggerName(), e.getTimeStamp(), e.getCallerData());
    }

    public void setCallback(String callback) throws ClassNotFoundException, NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException {
        this.callback = (LogHandler)Class.forName(callback).getConstructor().newInstance();
    }
}
