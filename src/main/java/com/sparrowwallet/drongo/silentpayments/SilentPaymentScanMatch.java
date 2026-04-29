package com.sparrowwallet.drongo.silentpayments;

/**
 * A single output match produced by {@link SilentPaymentUtils#scanTransactionOutputs}.
 * <p>
 * The {@code tweak} is the value to store on {@code WalletNode.silentPaymentTweak}: for an unlabeled
 * receive output it is {@code t_k}; for a labeled output it is {@code (t_k + label_m_priv) mod n} —
 * the combined scalar, so {@code Keystore.getKey/getPubKey} can derive the on-chain output key by
 * adding it directly to the base spend key, with no label awareness in the signing path.
 *
 * @param outputIndex the index of the matched output within the transaction
 * @param labelIndex {@code null} for an unlabeled receive match; {@code 0} for change; positive for labeled receive
 * @param tweak 32-byte scalar; the value to persist as the WalletNode's silent-payment tweak
 */
public record SilentPaymentScanMatch(int outputIndex, Integer labelIndex, byte[] tweak) {}
