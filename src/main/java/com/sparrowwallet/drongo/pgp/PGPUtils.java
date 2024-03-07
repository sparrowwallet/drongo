package com.sparrowwallet.drongo.pgp;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.gpg.keybox.KeyBlob;
import org.bouncycastle.gpg.keybox.PublicKeyRingBlob;
import org.bouncycastle.gpg.keybox.bc.BcKeyBox;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.util.io.Streams;
import org.pgpainless.PGPainless;
import org.pgpainless.decryption_verification.*;
import org.pgpainless.key.SubkeyIdentifier;
import org.pgpainless.util.ArmoredInputStreamFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;

public class PGPUtils {
    private static final Logger log = LoggerFactory.getLogger(PGPUtils.class);
    public static final String APPLICATION_KEYRING = "/gpg/pubkeys.asc";
    public static final String PUBRING_GPG = "pubring.gpg";
    public static final String PUBRING_KBX = "pubring.kbx";

    public static PGPVerificationResult verify(InputStream publicKeyStream, InputStream contentStream, InputStream detachedSignatureStream) throws IOException, PGPVerificationException {
        PGPPublicKeyRing publicKeyRing = null;
        if(publicKeyStream != null) {
            publicKeyRing = PGPainless.readKeyRing().publicKeyRing(publicKeyStream);
            if(publicKeyRing == null) {
                throw new PGPVerificationException("Invalid public key provided");
            }
        }

        PGPPublicKeyRingCollection userPgpPublicKeyRingCollection = getUserKeyRingCollection();
        PGPPublicKeyRingCollection appPgpPublicKeyRingCollection = getApplicationKeyRingCollection();

        try {
            ConsumerOptions options = ConsumerOptions.get();
            if(publicKeyRing != null) {
                options.addVerificationCert(publicKeyRing);
            }
            if(userPgpPublicKeyRingCollection != null) {
                options.addVerificationCerts(userPgpPublicKeyRingCollection);
            }
            if(appPgpPublicKeyRingCollection != null) {
                options.addVerificationCerts(appPgpPublicKeyRingCollection);
            }
            if(detachedSignatureStream != null) {
                options.addVerificationOfDetachedSignatures(detachedSignatureStream);
            }

            DecryptionStream verificationStream = PGPainless.decryptAndOrVerify()
                    .onInputStream(contentStream)
                    .withOptions(options);

            Streams.drain(verificationStream);
            verificationStream.close();

            MessageMetadata result = verificationStream.getMetadata();

            if(result.isVerifiedSigned()) {
                for(SignatureVerification signatureVerification : result.getVerifiedSignatures()) {
                    SubkeyIdentifier subkeyIdentifier = signatureVerification.getSigningKey();
                    if(subkeyIdentifier != null) {
                        PGPPublicKey signedByKey = null;
                        long primaryKeyId = subkeyIdentifier.getPrimaryKeyId();
                        PGPKeySource keySource;
                        if(publicKeyRing != null && publicKeyRing.getPublicKey(primaryKeyId) != null) {
                            signedByKey = publicKeyRing.getPublicKey(primaryKeyId);
                            keySource = PGPKeySource.USER;
                            log.debug("Signed using provided public key");
                        } else if(appPgpPublicKeyRingCollection != null && appPgpPublicKeyRingCollection.getPublicKey(primaryKeyId) != null
                                && !isExpired(appPgpPublicKeyRingCollection.getPublicKey(primaryKeyId))) {
                            signedByKey = appPgpPublicKeyRingCollection.getPublicKey(primaryKeyId);
                            keySource = PGPKeySource.APPLICATION;
                            log.debug("Signed using application public key");
                        } else if(userPgpPublicKeyRingCollection != null) {
                            signedByKey = userPgpPublicKeyRingCollection.getPublicKey(primaryKeyId);
                            keySource = PGPKeySource.GPG;
                            log.debug("Signed using user public key");
                        } else if(appPgpPublicKeyRingCollection != null && appPgpPublicKeyRingCollection.getPublicKey(primaryKeyId) != null) {
                            signedByKey = appPgpPublicKeyRingCollection.getPublicKey(primaryKeyId);
                            keySource = PGPKeySource.APPLICATION;
                            log.debug("Signed using expired application public key");
                        } else {
                            keySource = PGPKeySource.NONE;
                            log.debug("Could not find public key for primary key id " + primaryKeyId);
                        }

                        String fingerprint = subkeyIdentifier.getPrimaryKeyFingerprint().prettyPrint();
                        String userId = fingerprint;
                        boolean expired = false;
                        if(signedByKey != null) {
                            Iterator<String> userIds = signedByKey.getUserIDs();
                            if(userIds.hasNext()) {
                                userId = userIds.next();
                            }
                            expired = isExpired(signedByKey);
                        }

                        return new PGPVerificationResult(primaryKeyId, userId, fingerprint, signatureVerification.getSignature().getCreationTime(), expired, keySource);
                    }
                }
            }

            if(!result.getRejectedDetachedSignatures().isEmpty()) {
                throw new PGPVerificationException(result.getRejectedDetachedSignatures().get(0).getValidationException().getMessage());
            } else if(!result.getRejectedInlineSignatures().isEmpty()) {
                throw new PGPVerificationException(result.getRejectedInlineSignatures().get(0).getValidationException().getMessage());
            }

            throw new PGPVerificationException("No signatures found");
        } catch(Exception e) {
            log.warn("Failed to verify signature", e);
            throw new PGPVerificationException(e.getMessage());
        }
    }

    private static PGPPublicKeyRingCollection getApplicationKeyRingCollection() throws IOException {
        try(InputStream pubKeyStream = PGPUtils.class.getResourceAsStream(APPLICATION_KEYRING)) {
            if(pubKeyStream != null) {
                return PGPainless.readKeyRing().publicKeyRingCollection(pubKeyStream);
            }
        } catch(Exception e) {
            log.warn("Error loading application key rings", e);
        }

        return null;
    }

    private static PGPPublicKeyRingCollection getUserKeyRingCollection() {
        try {
            File gnupgHome = getGnuPGHome();
            if(gnupgHome.exists()) {
                File kbxPubRing = new File(gnupgHome, PUBRING_KBX);
                if(kbxPubRing.exists()) {
                    BcKeyBox bcKeyBox = new BcKeyBox(new FileInputStream(kbxPubRing));
                    List<PGPPublicKeyRing> rings = new ArrayList<>();
                    for(KeyBlob keyBlob : bcKeyBox.getKeyBlobs()) {
                        if(keyBlob instanceof PublicKeyRingBlob publicKeyRingBlob) {
                            rings.add(publicKeyRingBlob.getPGPPublicKeyRing());
                        }
                    }
                    if(!rings.isEmpty()) {
                        return new PGPPublicKeyRingCollection(rings);
                    }
                }

                File gpgPubRing = new File(gnupgHome, PUBRING_GPG);
                if(gpgPubRing.exists()) {
                    return PGPainless.readKeyRing().publicKeyRingCollection(new FileInputStream(gpgPubRing));
                }
            }
        } catch(Exception e) {
            log.warn("Error loading user key rings: " + e.getMessage());
        }

        return null;
    }

    private static File getGnuPGHome() {
        String gnupgHome = System.getenv("GNUPGHOME");
        if(gnupgHome != null && !gnupgHome.isEmpty()) {
            File envHome = new File(gnupgHome);
            if(envHome.exists()) {
                return envHome;
            }
        }

        if(isWindows()) {
            File winHome = new File(System.getenv("APPDATA"), "gnupg");
            if(winHome.exists()) {
                return winHome;
            }
        }

        return new File(System.getProperty("user.home"), ".gnupg");
    }

    private static boolean isWindows() {
        String osName = System.getProperty("os.name");
        return (osName != null && osName.toLowerCase(Locale.ROOT).startsWith("windows"));
    }

    public static boolean signatureContainsManifest(File signatureFile) {
        try(OpenPgpInputStream openPgpInputStream = new OpenPgpInputStream(new FileInputStream(signatureFile))) {
            openPgpInputStream.reset();

            if(openPgpInputStream.isAsciiArmored()) {
                ArmoredInputStream armorIn = ArmoredInputStreamFactory.get(openPgpInputStream);
                if(armorIn.isClearText()) {
                    return true;
                }
            }

            return openPgpInputStream.isLikelyOpenPgpMessage();
        } catch(IOException e) {
            log.debug("Error opening signature file", e);
            return false;
        }
    }

    public static boolean isExpired(PGPPublicKey publicKey) {
        long validSeconds = publicKey.getValidSeconds();
        if(validSeconds == 0) {
            return false;
        }

        Instant instant = publicKey.getCreationTime().toInstant();
        LocalDateTime creationDateTime = instant.atZone(ZoneId.systemDefault()).toLocalDateTime();
        LocalDateTime expiryDateTime = creationDateTime.plusSeconds(validSeconds);
        return expiryDateTime.isBefore(LocalDateTime.now());
    }
}
