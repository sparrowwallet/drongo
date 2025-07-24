package com.sparrowwallet.drongo.dns;

import org.xbill.DNS.*;
import org.xbill.DNS.Record;

import java.io.ByteArrayOutputStream;
import java.net.UnknownHostException;
import java.util.*;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Executor;

public class PersistingResolver extends SimpleResolver {
    private final Set<Record> chain = new LinkedHashSet<>();

    public PersistingResolver(String hostname) throws UnknownHostException {
        super(hostname);
    }

    @Override
    public CompletionStage<Message> sendAsync(Message query, Executor executor) {
        CompletionStage<Message> result = super.sendAsync(query, executor);
        return result.thenApply(response -> {
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
                if((r.getType() == Type.RRSIG && r.getRRsetType() == Type.NSEC && r.getRRsetType() == Type.NSEC3)|| r.getType() == Type.NSEC || r.getType() == Type.NSEC3) {
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
}
