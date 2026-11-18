package com.sparrowwallet.drongo.dns;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.*;

import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Executor;

public class AuthenticatingResolverTest {
    @Test
    public void noResponseIsNotAuthenticated() {
        Assertions.assertFalse(new AuthenticatingResolver(new StubResolver()).isAuthenticated());
    }

    @Test
    public void authenticatedResponsesAreAuthenticated() throws Exception {
        AuthenticatingResolver resolver = new AuthenticatingResolver(new StubResolver(true, true));
        send(resolver);
        send(resolver);
        Assertions.assertTrue(resolver.isAuthenticated());
    }

    @Test
    public void laterAuthenticatedResponseDoesNotAuthenticateLookup() throws Exception {
        AuthenticatingResolver resolver = new AuthenticatingResolver(new StubResolver(false, true));
        send(resolver);
        send(resolver);
        Assertions.assertFalse(resolver.isAuthenticated());
    }

    private static void send(Resolver resolver) throws Exception {
        Message query = Message.newQuery(org.xbill.DNS.Record.newRecord(Name.fromString("test.example."), Type.TXT, DClass.IN));
        resolver.sendAsync(query, Runnable::run).toCompletableFuture().get();
    }

    private static class StubResolver implements Resolver {
        private final Deque<Boolean> adFlags = new ArrayDeque<>();

        StubResolver(Boolean... adFlags) {
            this.adFlags.addAll(List.of(adFlags));
        }

        @Override
        public CompletionStage<Message> sendAsync(Message query, Executor executor) {
            Message response = new Message(query.getHeader().getID());
            response.getHeader().setFlag(Flags.QR);
            if(adFlags.removeFirst()) {
                response.getHeader().setFlag(Flags.AD);
            }
            return CompletableFuture.completedFuture(response);
        }

        @Override
        public void setPort(int port) {
        }

        @Override
        public void setTCP(boolean flag) {
        }

        @Override
        public void setIgnoreTruncation(boolean flag) {
        }

        @Override
        public void setEDNS(int version, int payloadSize, int flags, List<EDNSOption> options) {
        }

        @Override
        public void setTSIGKey(TSIG key) {
        }

        @Override
        public void setTimeout(Duration timeout) {
        }
    }
}
