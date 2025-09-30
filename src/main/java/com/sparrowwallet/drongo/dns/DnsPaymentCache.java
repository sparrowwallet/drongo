package com.sparrowwallet.drongo.dns;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;
import com.sparrowwallet.drongo.address.Address;
import com.sparrowwallet.drongo.silentpayments.SilentPayment;
import com.sparrowwallet.drongo.silentpayments.SilentPaymentAddress;
import com.sparrowwallet.drongo.wallet.Payment;

import java.util.concurrent.TimeUnit;

public class DnsPaymentCache {
    public static final long MAX_TTL_SECONDS = 604800L;
    public static final long MIN_TTL_SECONDS = 1800L;

    private static final Cache<DnsAddress, DnsPayment> dnsPayments = Caffeine.newBuilder().expireAfter(new Expiry<DnsAddress, DnsPayment>() {
        @Override
        public long expireAfterCreate(DnsAddress address, DnsPayment dnsPayment, long currentTime) {
            return TimeUnit.SECONDS.toNanos(Math.max(dnsPayment.getTTL(), MIN_TTL_SECONDS));
        }

        @Override
        public long expireAfterUpdate(DnsAddress address, DnsPayment dnsPayment, long currentTime, long currentDuration) {
            return expireAfterCreate(address, dnsPayment, currentTime);
        }

        @Override
        public long expireAfterRead(DnsAddress address, DnsPayment dnsPayment, long currentTime, long currentDuration) {
            return currentDuration;
        }
    }).build();

    private DnsPaymentCache() {}

    public static DnsPayment getDnsPayment(Address address) {
        return dnsPayments.getIfPresent(new DnsAddress(address));
    }

    public static DnsPayment getDnsPayment(SilentPaymentAddress silentPaymentAddress) {
        return dnsPayments.getIfPresent(new DnsAddress(silentPaymentAddress));
    }

    public static DnsPayment getDnsPayment(Payment payment) {
        if(payment instanceof SilentPayment silentPayment) {
            return dnsPayments.getIfPresent(new DnsAddress(silentPayment.getSilentPaymentAddress()));
        } else {
            return dnsPayments.getIfPresent(new DnsAddress(payment.getAddress()));
        }
    }

    public static DnsPayment getDnsPayment(String hrn) {
        for(DnsPayment dnsPayment : dnsPayments.asMap().values()) {
            if(dnsPayment.hrn().equals(hrn)) {
                return dnsPayment;
            }
        }

        return null;
    }

    public static void putDnsPayment(Address address, DnsPayment dnsPayment) {
        dnsPayments.put(new DnsAddress(address), dnsPayment);
    }

    public static void putDnsPayment(SilentPaymentAddress silentPaymentAddress, DnsPayment dnsPayment) {
        dnsPayments.put(new DnsAddress(silentPaymentAddress), dnsPayment);
    }
}
