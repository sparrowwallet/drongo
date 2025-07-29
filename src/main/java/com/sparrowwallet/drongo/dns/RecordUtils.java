package com.sparrowwallet.drongo.dns;

import org.xbill.DNS.*;
import org.xbill.DNS.Record;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class RecordUtils {
    public static org.xbill.DNS.Record fromWire(DNSInput in, int section, boolean isUpdate) throws WireParseException {
        int type;
        int dclass;
        long ttl;
        int length;
        Name name;

        name = new Name(in);
        type = in.readU16();
        dclass = in.readU16();

        if(section == Section.QUESTION) {
            return org.xbill.DNS.Record.newRecord(name, type, dclass);
        }

        ttl = in.readU32();
        length = in.readU16();
        if(length == 0 && isUpdate && (section == Section.PREREQ || section == Section.UPDATE)) {
            return org.xbill.DNS.Record.newRecord(name, type, dclass, ttl);
        }

        return Record.newRecord(name, type, dclass, ttl, length, in.readByteArray(length));
    }

    public static Map<Record, String> checkSecurityConstraints(List<Record> section) {
        Map<Record, String> warnings = new HashMap<>();
        if(section != null) {
            for(Record record : section) {
                if(record.getType() == Type.RRSIG) {
                    RRSIGRecord rrsig = (RRSIGRecord)record;
                    if(rrsig.getAlgorithm() == DNSSEC.Algorithm.RSASHA1 || rrsig.getAlgorithm() == DNSSEC.Algorithm.RSA_NSEC3_SHA1) {
                        warnings.put(record, "Record contains weak SHA-1 based signature");
                    }
                } else if(record.getType() == Type.DNSKEY) {
                    DNSKEYRecord dnskey = (DNSKEYRecord)record;
                    if(dnskey.getAlgorithm() == DNSSEC.Algorithm.RSASHA1 || dnskey.getAlgorithm() == DNSSEC.Algorithm.RSA_NSEC3_SHA1 ||
                            dnskey.getAlgorithm() == DNSSEC.Algorithm.RSASHA256 || dnskey.getAlgorithm() == DNSSEC.Algorithm.RSASHA512) {
                        try {
                            java.security.PublicKey publicKey = dnskey.getPublicKey();
                            if(publicKey instanceof java.security.interfaces.RSAPublicKey rsaKey) {
                                int keyLength = rsaKey.getModulus().bitLength();
                                if(keyLength < 1024) {
                                    warnings.put(record, "Record contains weak RSA public key with key length of " + keyLength + " bits");
                                }
                            }
                        } catch(DNSSEC.DNSSECException e) {
                            warnings.put(record, "Record contains invalid public key");
                        }
                    }
                }
            }
        }

        return warnings;
    }

    /**
     * Determine by looking at a signed RRset whether the RRset name was the result of a wildcard
     * expansion. If so, return the name of the generating wildcard.
     *
     * @param rrset The rrset to chedck.
     * @return the wildcard name, if the rrset was synthesized from a wildcard. null if not.
     */
    public static Name rrsetWildcard(RRset rrset) {
        List<RRSIGRecord> sigs = rrset.sigs();
        RRSIGRecord firstSig = sigs.getFirst();

        // check rest of signatures have identical label count
        for(int i = 1; i < sigs.size(); i++) {
            if(sigs.get(i).getLabels() != firstSig.getLabels()) {
                throw new IllegalArgumentException("Label count mismatch on RRSIGs");
            }
        }

        // if the RRSIG label count is shorter than the number of actual labels,
        // then this rrset was synthesized from a wildcard.
        // Note that the RRSIG label count doesn't count the root label.
        Name wn = rrset.getName();

        // skip a leading wildcard label in the dname (RFC4035 2.2)
        if(rrset.getName().isWild()) {
            wn = new Name(wn, 1);
        }

        int labelDiff = (wn.labels() - 1) - firstSig.getLabels();
        if(labelDiff > 0) {
            return wn.wild(labelDiff);
        }

        return null;
    }

    /**
     * Finds the longest domain name in common with the given name.
     *
     * @param domain1 The first domain to process.
     * @param domain2 The second domain to process.
     * @return The longest label in common of domain1 and domain2. The least common name is the root.
     */
    public static Name longestCommonName(Name domain1, Name domain2) {
        int l = Math.min(domain1.labels(), domain2.labels());
        domain1 = new Name(domain1, domain1.labels() - l);
        domain2 = new Name(domain2, domain2.labels() - l);
        for(int i = 0; i < l - 1; i++) {
            Name ns1 = new Name(domain1, i);
            if(ns1.equals(new Name(domain2, i))) {
                return ns1;
            }
        }

        return Name.root;
    }
}
