package com.craigraw.drongo.psbt;

import com.craigraw.drongo.KeyDerivation;
import com.craigraw.drongo.crypto.ECKey;
import com.craigraw.drongo.crypto.LazyECPoint;
import com.craigraw.drongo.protocol.Script;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class PSBTOutput {
    public static final byte PSBT_OUT_REDEEM_SCRIPT = 0x00;
    public static final byte PSBT_OUT_WITNESS_SCRIPT = 0x01;
    public static final byte PSBT_OUT_BIP32_DERIVATION = 0x02;
    public static final byte PSBT_OUT_PROPRIETARY = (byte)0xfc;

    private Script redeemScript;
    private Script witnessScript;
    private Map<LazyECPoint, KeyDerivation> derivedPublicKeys = new LinkedHashMap<>();
    private Map<String, String> proprietary = new LinkedHashMap<>();

    private static final Logger log = LoggerFactory.getLogger(PSBTOutput.class);

    PSBTOutput(List<PSBTEntry> outputEntries) {
        for(PSBTEntry entry : outputEntries) {
            switch (entry.getKeyType()) {
                case PSBT_OUT_REDEEM_SCRIPT:
                    entry.checkOneByteKey();
                    Script redeemScript = new Script(entry.getData());
                    this.redeemScript = redeemScript;
                    log.debug("Found output redeem script hex " + Hex.toHexString(redeemScript.getProgram()) + " script " + redeemScript);
                    break;
                case PSBT_OUT_WITNESS_SCRIPT:
                    entry.checkOneByteKey();
                    Script witnessScript = new Script(entry.getData());
                    this.witnessScript = witnessScript;
                    log.debug("Found output witness script hex " + Hex.toHexString(witnessScript.getProgram()) + " script " + witnessScript);
                    break;
                case PSBT_OUT_BIP32_DERIVATION:
                    entry.checkOneBytePlusPubKey();
                    LazyECPoint publicKey = new LazyECPoint(ECKey.CURVE.getCurve(), entry.getKeyData());
                    KeyDerivation keyDerivation = PSBTEntry.parseKeyDerivation(entry.getData());
                    this.derivedPublicKeys.put(publicKey, keyDerivation);
                    log.debug("Found output bip32_derivation with master fingerprint " + keyDerivation.getMasterFingerprint() + " at path " + keyDerivation.getDerivationPath() + " public key " + publicKey);
                    break;
                case PSBT_OUT_PROPRIETARY:
                    proprietary.put(Hex.toHexString(entry.getKeyData()), Hex.toHexString(entry.getData()));
                    log.debug("Found proprietary output " + Hex.toHexString(entry.getKeyData()) + ": " + Hex.toHexString(entry.getData()));
                    break;
                default:
                    log.warn("PSBT output not recognized key type: " + entry.getKeyType());
            }
        }
    }

    public Script getRedeemScript() {
        return redeemScript;
    }

    public Script getWitnessScript() {
        return witnessScript;
    }

    public KeyDerivation getKeyDerivation(LazyECPoint publicKey) {
        return derivedPublicKeys.get(publicKey);
    }

    public Map<LazyECPoint, KeyDerivation> getDerivedPublicKeys() {
        return derivedPublicKeys;
    }

    public Map<String, String> getProprietary() {
        return proprietary;
    }
}
