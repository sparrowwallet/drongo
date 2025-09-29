package com.sparrowwallet.drongo.dns;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;
import com.sparrowwallet.drongo.address.Address;
import com.sparrowwallet.drongo.silentpayments.SilentPayment;
import com.sparrowwallet.drongo.silentpayments.SilentPaymentAddress;
import com.sparrowwallet.drongo.wallet.Payment;
import org.checkerframework.checker.index.qual.NonNegative;
import org.checkerframework.checker.nullness.qual.NonNull;

import java.util.concurrent.TimeUnit;

public class DnsPaymentCache {
    public static final long MAX_TTL_SECONDS = 604800L;
    public static final long MIN_TTL_SECONDS = 1800L;

    private static final Cache<@NonNull DnsAddress, @NonNull DnsPayment> dnsPayments = Caffeine.newBuilder().expireAfter(new Expiry<@NonNull DnsAddress, @NonNull DnsPayment>() {
        @Override
        public long expireAfterCreate(@NonNull DnsAddress address, @NonNull DnsPayment dnsPayment, long currentTime) {
            return TimeUnit.SECONDS.toNanos(Math.max(dnsPayment.getTTL(), MIN_TTL_SECONDS));
        }

        @Override
        public long expireAfterUpdate(@NonNull DnsAddress address, @NonNull DnsPayment dnsPayment, long currentTime, @NonNegative long currentDuration) {
            return expireAfterCreate(address, dnsPayment, currentTime);
        }

        @Override
        public long expireAfterRead(@NonNull DnsAddress address, @NonNull DnsPayment dnsPayment, long currentTime, @NonNegative long currentDuration) {
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
