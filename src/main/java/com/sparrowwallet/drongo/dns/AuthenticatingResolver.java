package com.sparrowwallet.drongo.dns;

import org.xbill.DNS.*;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Executor;

public class AuthenticatingResolver implements Resolver {
    private final Resolver delegate;
    private boolean authenticated;

    public AuthenticatingResolver(Resolver delegate) {
        this.delegate = delegate;
    }

    @Override
    public void setPort(int port) {
        delegate.setPort(port);
    }

    @Override
    public void setTCP(boolean flag) {
        delegate.setTCP(flag);
    }

    @Override
    public void setIgnoreTruncation(boolean flag) {
        delegate.setIgnoreTruncation(flag);
    }

    @Override
    public void setEDNS(int version, int payloadSize, int flags, List<EDNSOption> options) {
        delegate.setEDNS(version, payloadSize, flags, options);
    }

    @Override
    public void setTSIGKey(TSIG key) {
        delegate.setTSIGKey(key);
    }

    @Override
    public void setTimeout(Duration timeout) {
        delegate.setTimeout(timeout);
    }

    @Override
    public CompletionStage<Message> sendAsync(Message query, Executor executor) {
        return delegate.sendAsync(query, executor).thenApply(response -> {
            this.authenticated = response.getHeader().getFlag(Flags.AD);
            return response;
        });
    }

    public boolean isAuthenticated() {
        return authenticated;
    }
}
