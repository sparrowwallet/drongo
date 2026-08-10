package com.sparrowwallet.drongo.dns;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.*;
import org.xbill.DNS.Record;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Proxy;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Executor;

public class PersistingResolver extends SimpleResolver implements Closeable {
    private static final Logger log = LoggerFactory.getLogger(PersistingResolver.class);

    private final Set<Record> chain = new LinkedHashSet<>();
    private final Proxy proxy;
    private Socket socket;

    public PersistingResolver(String hostname) throws UnknownHostException {
        this(hostname, null);
    }

    public PersistingResolver(String hostname, Proxy proxy) throws UnknownHostException {
        super(hostname);
        this.proxy = proxy;
    }

    @Override
    public CompletionStage<Message> sendAsync(Message query, Executor executor) {
        CompletionStage<Message> result = (proxy == null ? super.sendAsync(query, executor) : sendProxiedAsync(query, executor));
        return result.thenApply(response -> {
            if(log.isDebugEnabled()) {
                log.debug(responseToString(query, response));
            }

            addAnswerSectionToChain(response.getSection(Section.ANSWER));
            addAuthoritySectionToChain(response.getSection(Section.AUTHORITY));
            return response;
        });
    }

    /**
     * Sends the query over TCP via the configured SOCKS proxy, since the NIO based transport in SimpleResolver cannot be proxied.
     * Note that message level concerns are handled here rather than by SimpleResolver, although DNSSEC validation still occurs in ValidatingResolver above.
     * The connection is kept alive between queries to avoid paying the proxy stream setup cost for every query in a validated lookup, and released via {@link #close()}.
     */
    private CompletionStage<Message> sendProxiedAsync(Message query, Executor executor) {
        Message ednsQuery = query.clone();
        OPTRecord opt = getEDNS();
        if(opt != null && ednsQuery.getOPT() == null) {
            ednsQuery.addRecord(opt, Section.ADDITIONAL);
        }

        CompletableFuture<Message> future = new CompletableFuture<>();
        executor.execute(() -> {
            try {
                future.complete(sendProxied(ednsQuery));
            } catch(Throwable t) {
                future.completeExceptionally(t);
            }
        });

        return future;
    }

    private synchronized Message sendProxied(Message query) throws IOException {
        byte[] wireQuery = query.toWire(Message.MAXLENGTH);
        boolean reusing = (socket != null);
        try {
            return exchange(wireQuery, query);
        } catch(IOException e) {
            closeSocket();
            if(!reusing) {
                throw e;
            }
        }

        try {
            return exchange(wireQuery, query);
        } catch(IOException e) {
            closeSocket();
            throw e;
        }
    }

    private Message exchange(byte[] wireQuery, Message query) throws IOException {
        int timeoutMillis = (int)getTimeout().toMillis();
        if(socket == null) {
            socket = new Socket(proxy);
            socket.connect(getAddress(), timeoutMillis);
        }
        socket.setSoTimeout(timeoutMillis);
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        out.writeShort(wireQuery.length);
        out.write(wireQuery);
        out.flush();
        DataInputStream in = new DataInputStream(socket.getInputStream());
        byte[] wireResponse = new byte[in.readUnsignedShort()];
        in.readFully(wireResponse);

        return parseResponse(query, wireResponse);
    }

    private void closeSocket() {
        if(socket != null) {
            try {
                socket.close();
            } catch(IOException e) {
                //ignore
            }
            socket = null;
        }
    }

    @Override
    public synchronized void close() {
        closeSocket();
    }

    private static Message parseResponse(Message query, byte[] wireResponse) throws IOException {
        if(wireResponse.length < Header.LENGTH) {
            throw new WireParseException("invalid DNS header - too short");
        }

        int id = ((wireResponse[0] & 0xFF) << 8) + (wireResponse[1] & 0xFF);
        int qid = query.getHeader().getID();
        if(id != qid) {
            throw new WireParseException("invalid message id: expected " + qid + "; got id " + id);
        }

        Message response = new Message(wireResponse);
        Record question = query.getQuestion();
        Record responseQuestion = response.getQuestion();
        if(question != null && (responseQuestion == null || !question.getName().equals(responseQuestion.getName())
                || question.getDClass() != responseQuestion.getDClass() || question.getType() != responseQuestion.getType())) {
            throw new WireParseException("invalid message: response question does not match query");
        }

        return response;
    }

    private void addAnswerSectionToChain(List<org.xbill.DNS.Record> section) {
        if(section != null) {
            chain.addAll(section);
        }
    }

    private void addAuthoritySectionToChain(List<Record> section) {
        if(section != null) {
            for(Record r : section) {
                if((r.getType() == Type.RRSIG && (r.getRRsetType() == Type.NSEC || r.getRRsetType() == Type.NSEC3)) || r.getType() == Type.NSEC || r.getType() == Type.NSEC3) {
                    chain.add(r);
                }
            }
        }
    }

    public Set<Record> getChain() {
        return chain;
    }

    public byte[] chainToWire() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        List<Record> sorted = new ArrayList<>(chain);
        Collections.sort(sorted);
        for(Record record : sorted) {
            baos.writeBytes(record.toWireCanonical());
        }

        return baos.toByteArray();
    }

    private static String responseToString(Message query, Message response) {
        StringBuilder sb = new StringBuilder();
        sb.append("Query for ").append(query.getQuestion().getName()).append(" returned:\n");
        sb.append("Answer section:\n");
        response.getSection(Section.ANSWER).stream().forEach(rr -> sb.append(rr).append("\n"));
        sb.append("Authority section:\n");
        response.getSection(Section.AUTHORITY).stream().forEach(rr -> sb.append(rr).append("\n"));
        sb.append("\n");
        return sb.toString();
    }
}
