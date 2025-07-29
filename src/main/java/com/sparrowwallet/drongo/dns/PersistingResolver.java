package com.sparrowwallet.drongo.dns;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.*;
import org.xbill.DNS.Record;

import java.io.ByteArrayOutputStream;
import java.net.UnknownHostException;
import java.util.*;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Executor;

public class PersistingResolver extends SimpleResolver {
    private static final Logger log = LoggerFactory.getLogger(PersistingResolver.class);

    private final Set<Record> chain = new LinkedHashSet<>();

    public PersistingResolver(String hostname) throws UnknownHostException {
        super(hostname);
    }

    @Override
    public CompletionStage<Message> sendAsync(Message query, Executor executor) {
        CompletionStage<Message> result = super.sendAsync(query, executor);
        return result.thenApply(response -> {
            if(log.isDebugEnabled()) {
                log.debug(responseToString(query, response));
            }

            addAnswerSectionToChain(response.getSection(Section.ANSWER));
            addAuthoritySectionToChain(response.getSection(Section.AUTHORITY));
            return response;
        });
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
