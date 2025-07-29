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
        Message response = makeNoErrorResponse(query);
        addRecords(query.getQuestion(), response);

        if(response.getSection(Section.ANSWER).isEmpty() && response.getSection(Section.AUTHORITY).isEmpty()) {
            response = makeNoDomainResponse(query);
        }

        return CompletableFuture.completedFuture(response);
    }

    private void addRecords(Record question, Message response) {
        Name name = question.getName();

        RRset cnameSet = getRRSet(name, Type.CNAME, question.getDClass());
        addRRSetToMessage(response, cnameSet);

        if(!cnameSet.rrs().isEmpty() && cnameSet.rrs().getFirst() instanceof CNAMERecord cnameRecord) {
            name = cnameRecord.getTarget();
        }

        RRset answerSet = getRRSet(name, question.getType(), question.getDClass());
        addRRSetToMessage(response, answerSet);
    }

    private void addRRSetToMessage(Message response, RRset rrset) {
        rrset.rrs().stream().forEach(it -> response.addRecord(it, Section.ANSWER));
        rrset.sigs().stream().forEach(it -> response.addRecord(it, Section.ANSWER));

        if(!rrset.sigs().isEmpty()) {
            Name wildcard = RecordUtils.rrsetWildcard(rrset);
            if(wildcard != null) {
                RRset nsecRRset = getNSecRRSetForWildcard(wildcard);
                nsecRRset.rrs().stream().forEach(it -> response.addRecord(it, Section.AUTHORITY));
                nsecRRset.sigs().stream().forEach(it -> response.addRecord(it, Section.AUTHORITY));
            }
        }
    }

    private RRset getRRSet(Name name, int type, int dclass) {
        RRset rrset = new RRset();
        for(Record it : cachedRrs) {
            if(it.getName().equals(name) && it.getType() == type && it.getDClass() == dclass) {
                rrset.addRR(it);
            }
        }

        for(RRSIGRecord it : cachedSigs) {
            if(it.getName().equals(name) && it.getTypeCovered() == type && it.getDClass() == dclass) {
                rrset.addRR(it);
            }
        }

        return rrset;
    }

    private RRset getNSecRRSetForWildcard(Name wildcard) {
        RRset rrset = new RRset();

        for(Record it : cachedRrs) {
            if((it.getType() == Type.NSEC || it.getType() == Type.NSEC3) && RecordUtils.longestCommonName(it.getName(), wildcard) != Name.root) {
                rrset.addRR(it);
            }
        }

        for(RRSIGRecord it : cachedSigs) {
            if((it.getTypeCovered() == Type.NSEC || it.getTypeCovered() == Type.NSEC3) && RecordUtils.longestCommonName(it.getName(), wildcard) != Name.root) {
                rrset.addRR(it);
            }
        }

        return rrset;
    }

    private Message makeNoDomainResponse(Message query) {
        Header messageHeader = new Header();
        messageHeader.setID(query.getHeader().getID());
        messageHeader.setRcode(Rcode.NXDOMAIN);
        messageHeader.setFlag(Flags.QR);
        messageHeader.setFlag(Flags.CD);
        messageHeader.setFlag(Flags.RD);
        messageHeader.setFlag(Flags.RA);

        Message answerMessage = new Message();
        answerMessage.setHeader(messageHeader);

        for(Record record : query.getSection(Section.QUESTION)) {
            answerMessage.addRecord(record, Section.QUESTION);
        }

        return answerMessage;
    }

    private Message makeNoErrorResponse(Message query) {
        Header messageHeader = new Header();
        messageHeader.setID(query.getHeader().getID());
        messageHeader.setRcode(Rcode.NOERROR);
        messageHeader.setFlag(Flags.QR);
        messageHeader.setFlag(Flags.CD);
        messageHeader.setFlag(Flags.RD);
        messageHeader.setFlag(Flags.RA);

        Message answerMessage = new Message();
        answerMessage.setHeader(messageHeader);

        for(Record record : query.getSection(Section.QUESTION)) {
            answerMessage.addRecord(record, Section.QUESTION);
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
