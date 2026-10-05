package com.sparrowwallet.drongo.pgp;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.DocumentSignatureType;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.encryption_signing.SigningOptions;
import org.pgpainless.key.protection.SecretKeyRingProtector;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

public class PGPUtilsTest {
    private static final String MANIFEST = "1111111111111111111111111111111111111111111111111111111111111111  release-1.0.tar.gz\n";
    private static final String TRAILER = "2222222222222222222222222222222222222222222222222222222222222222  release-1.0.tar.gz\n";

    private static PGPSecretKeyRing secretKeys;
    private static PGPPublicKeyRing publicKeys;

    @TempDir
    File tempDir;

    @BeforeAll
    public static void setUp() throws Exception {
        secretKeys = PGPainless.generateKeyRing().modernKeyRing("Test <test@example.com>");
        publicKeys = PGPainless.extractCertificate(secretKeys);
    }

    private static EncryptionStream sign(byte[] content, ProducerOptions producerOptions, ByteArrayOutputStream out) throws Exception {
        EncryptionStream signingStream = PGPainless.encryptAndOrSign().onOutputStream(out).withOptions(producerOptions);
        Streams.pipeAll(new ByteArrayInputStream(content), signingStream);
        signingStream.close();
        return signingStream;
    }

    private static byte[] signClearsigned(byte[] content) throws Exception {
        SigningOptions signingOptions = SigningOptions.get().addDetachedSignature(SecretKeyRingProtector.unprotectedKeys(), secretKeys, DocumentSignatureType.CANONICAL_TEXT_DOCUMENT);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        sign(content, ProducerOptions.sign(signingOptions).setCleartextSigned(), out);
        return out.toByteArray();
    }

    private static byte[] signInline(byte[] content) throws Exception {
        SigningOptions signingOptions = SigningOptions.get().addInlineSignature(SecretKeyRingProtector.unprotectedKeys(), secretKeys, DocumentSignatureType.BINARY_DOCUMENT);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        sign(content, ProducerOptions.sign(signingOptions).setAsciiArmor(true), out);
        return out.toByteArray();
    }

    private static PGPSignature signDetached(byte[] content) throws Exception {
        SigningOptions signingOptions = SigningOptions.get().addDetachedSignature(SecretKeyRingProtector.unprotectedKeys(), secretKeys, DocumentSignatureType.BINARY_DOCUMENT);
        EncryptionStream signingStream = sign(content, ProducerOptions.sign(signingOptions), new ByteArrayOutputStream());
        return signingStream.getResult().getDetachedSignatures().values().iterator().next().iterator().next();
    }

    @Test
    public void clearsignedOutputsSignedText() throws Exception {
        byte[] clearsigned = signClearsigned(MANIFEST.getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream file = new ByteArrayOutputStream();
        file.write(clearsigned);
        file.write(TRAILER.getBytes(StandardCharsets.UTF_8));

        ByteArrayOutputStream signedContent = new ByteArrayOutputStream();
        PGPVerificationResult result = PGPUtils.verify(new ByteArrayInputStream(publicKeys.getEncoded()), new ByteArrayInputStream(file.toByteArray()), null, signedContent);

        Assertions.assertEquals(PGPKeySource.USER, result.keySource());
        Assertions.assertEquals(MANIFEST.trim(), signedContent.toString(StandardCharsets.UTF_8).trim());
    }

    @Test
    public void inlineSignedOutputsSignedContent() throws Exception {
        byte[] content = MANIFEST.getBytes(StandardCharsets.UTF_8);
        byte[] inlineSigned = signInline(content);
        File inlineSignedFile = new File(tempDir, "manifest.txt.asc");
        Files.write(inlineSignedFile.toPath(), inlineSigned);
        Assertions.assertTrue(PGPUtils.signatureContainsManifest(inlineSignedFile));

        ByteArrayOutputStream signedContent = new ByteArrayOutputStream();
        PGPVerificationResult result = PGPUtils.verify(new ByteArrayInputStream(publicKeys.getEncoded()), new ByteArrayInputStream(inlineSigned), null, signedContent);

        Assertions.assertEquals(PGPKeySource.USER, result.keySource());
        Assertions.assertArrayEquals(content, signedContent.toByteArray());

        String armored = new String(inlineSigned, StandardCharsets.UTF_8);
        byte[] headerWhitespace = armored.replaceFirst("-----BEGIN PGP MESSAGE-----", "-----BEGIN PGP MESSAGE-----  ").getBytes(StandardCharsets.UTF_8);
        File headerWhitespaceFile = new File(tempDir, "manifest-whitespace.txt.asc");
        Files.write(headerWhitespaceFile.toPath(), headerWhitespace);
        Assertions.assertTrue(PGPUtils.signatureContainsManifest(headerWhitespaceFile));

        ByteArrayOutputStream headerWhitespaceContent = new ByteArrayOutputStream();
        PGPUtils.verify(new ByteArrayInputStream(publicKeys.getEncoded()), new ByteArrayInputStream(headerWhitespace), null, headerWhitespaceContent);
        Assertions.assertArrayEquals(content, headerWhitespaceContent.toByteArray());
    }

    @Test
    public void detachedOutputsContent() throws Exception {
        byte[] content = MANIFEST.getBytes(StandardCharsets.UTF_8);
        PGPSignature signature = signDetached(content);

        File signatureFile = new File(tempDir, "manifest.txt.asc");
        Files.writeString(signatureFile.toPath(), PGPainless.asciiArmor(signature));
        Assertions.assertFalse(PGPUtils.signatureContainsManifest(signatureFile));

        ByteArrayOutputStream signedContent = new ByteArrayOutputStream();
        PGPVerificationResult result = PGPUtils.verify(new ByteArrayInputStream(publicKeys.getEncoded()), new ByteArrayInputStream(content), new ByteArrayInputStream(signature.getEncoded()), signedContent);

        Assertions.assertEquals(PGPKeySource.USER, result.keySource());
        Assertions.assertArrayEquals(content, signedContent.toByteArray());
    }

    @Test
    public void detachedRejectsChangedContent() throws Exception {
        byte[] signature = signDetached(MANIFEST.getBytes(StandardCharsets.UTF_8)).getEncoded();
        byte[] content = (MANIFEST + TRAILER).getBytes(StandardCharsets.UTF_8);

        Assertions.assertThrows(PGPVerificationException.class,
                () -> PGPUtils.verify(new ByteArrayInputStream(publicKeys.getEncoded()), new ByteArrayInputStream(content), new ByteArrayInputStream(signature), new ByteArrayOutputStream()));
    }
}
