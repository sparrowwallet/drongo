package com.sparrowwallet.drongo.dns;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;
import com.sparrowwallet.drongo.address.Address;
import org.checkerframework.checker.index.qual.NonNegative;
import org.checkerframework.checker.nullness.qual.NonNull;

import java.util.concurrent.TimeUnit;

public class DnsPaymentCache {
    public static final long MAX_TTL_SECONDS = 604800L;
    public static final long MIN_TTL_SECONDS = 1800L;

    private static final Cache<@NonNull Address, @NonNull DnsPayment> dnsPayments = Caffeine.newBuilder().expireAfter(new Expiry<@NonNull Address, @NonNull DnsPayment>() {
        @Override
        public long expireAfterCreate(@NonNull Address address, @NonNull DnsPayment dnsPayment, long currentTime) {
            return TimeUnit.SECONDS.toNanos(Math.max(dnsPayment.getTTL(), MIN_TTL_SECONDS));
        }

        @Override
        public long expireAfterUpdate(@NonNull Address address, @NonNull DnsPayment dnsPayment, long currentTime, @NonNegative long currentDuration) {
            return expireAfterCreate(address, dnsPayment, currentTime);
        }

        @Override
        public long expireAfterRead(@NonNull Address address, @NonNull DnsPayment dnsPayment, long currentTime, @NonNegative long currentDuration) {
            return currentDuration;
        }
    }).build();

    private DnsPaymentCache() {}

    public static DnsPayment getDnsPayment(Address address) {
        return dnsPayments.getIfPresent(address);
    }

    public static void putDnsPayment(Address address, DnsPayment dnsPayment) {
        dnsPayments.put(address, dnsPayment);
    }
}
