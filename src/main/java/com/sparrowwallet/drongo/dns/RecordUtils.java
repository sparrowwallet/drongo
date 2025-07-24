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
}
