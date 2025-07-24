package com.sparrowwallet.drongo.dns;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Executor;

import org.xbill.DNS.*;
import org.xbill.DNS.Record;

import static com.sparrowwallet.drongo.dns.RecordUtils.fromWire;

public class OfflineResolver implements Resolver {
    private final List<Record> cachedRrs = new ArrayList<>();
    private final List<RRSIGRecord> cachedSigs = new ArrayList<>();

    public OfflineResolver(byte[] chain) throws WireParseException {
        DNSInput in = new DNSInput(chain);
        while(in.remaining() > 0) {
            Record record = fromWire(in, Section.ANSWER, false);
            if(record instanceof RRSIGRecord rrsig) {
                cachedSigs.add(rrsig);
            } else {
                cachedRrs.add(record);
            }
        }
    }

    @Override
    public void setPort(int port) {
        throw new UnsupportedOperationException("Unsupported");
    }

    @Override
    public void setTCP(boolean flag) {
        throw new UnsupportedOperationException("Unsupported");
    }

    // No-op
    @Override
    public void setIgnoreTruncation(boolean flag) {}

    // No-op
    @Override
    public void setEDNS(int level, int payloadSize, int flags, List<EDNSOption> options) {}

    @Override
    public void setTSIGKey(TSIG key) {
        throw new UnsupportedOperationException("Unsupported");
    }

    @Override
    public void setTimeout(Duration timeout) {
        throw new UnsupportedOperationException("Unsupported");
    }

    @Override
    public CompletionStage<Message> sendAsync(Message query, Executor executor) {
        Record question = query.getQuestion();
        List<Record> records = new ArrayList<>();

        for(Record it : cachedRrs) {
            if(it.getName().equals(question.getName()) && it.getType() == question.getType() && it.getDClass() == question.getDClass()) {
                records.add(it);
            }
        }

        for(RRSIGRecord it : cachedSigs) {
            if(it.getName().equals(question.getName()) && it.getTypeCovered() == question.getType() && it.getDClass() == question.getDClass()) {
                records.add(it);
            }
        }

        Message response;
        if(records.isEmpty()) {
            response = makeEmptyResponse(query);
        } else {
            response = makeResponseForRecords(records, query);
        }

        return CompletableFuture.completedFuture(response);
    }

    private Message makeEmptyResponse(Message query) {
        Header messageHeader = new Header();
        messageHeader.setID(query.getHeader().getID());
        messageHeader.setRcode(Rcode.NXDOMAIN);
        messageHeader.setFlag(Flags.QR);
        messageHeader.setFlag(Flags.CD);
        messageHeader.setFlag(Flags.RD);
        messageHeader.setFlag(Flags.RA);

        Message answerMessage = new Message();
        answerMessage.setHeader(messageHeader);

        return answerMessage;
    }

    private Message makeResponseForRecords(List<Record> records, Message query) {
        Message answerMessage = new Message();

        Header messageHeader = new Header();
        messageHeader.setID(query.getHeader().getID());
        messageHeader.setRcode(Rcode.NOERROR);
        messageHeader.setFlag(Flags.QR);
        messageHeader.setFlag(Flags.CD);
        messageHeader.setFlag(Flags.RD);
        messageHeader.setFlag(Flags.RA);
        answerMessage.setHeader(messageHeader);

        for(Record record : query.getSection(Section.QUESTION)) {
            answerMessage.addRecord(record, Section.QUESTION);
        }

        for(Record record : records) {
            answerMessage.addRecord(record, Section.ANSWER);
        }

        return answerMessage;
    }

    public List<Record> getCachedRrs() {
        return cachedRrs;
    }

    public List<RRSIGRecord> getCachedSigs() {
        return cachedSigs;
    }

    public List<Record> getRecords() {
        List<Record> records = new ArrayList<>(cachedRrs);
        records.addAll(cachedSigs);
        return records;
    }
}
