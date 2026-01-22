package org.codehaus.mojo.keytool.services;

import javax.inject.Named;
import javax.inject.Singleton;
import javax.security.auth.x500.X500Principal;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import org.apache.maven.plugin.MojoExecutionException;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Service for certificate and key pair generation using Bouncy Castle.
 * Follows SOLID principles - Single Responsibility: manages certificate generation operations.
 *
 * @since 2.0
 */
@Named
@Singleton
public class CertificateGenerationService {

    private static final Logger log = LoggerFactory.getLogger(CertificateGenerationService.class);

    /**
     * Generate a key pair and self-signed certificate.
     */
    public void generateKeyPair(
            File keystore,
            String storetype,
            char[] storepass,
            String alias,
            String keyalg,
            int keysize,
            String sigalg,
            String dname,
            int validity,
            char[] keypass,
            List<String> exts)
            throws MojoExecutionException {

        try {
            // Add Bouncy Castle provider
            java.security.Security.addProvider(new BouncyCastleProvider());

            // Generate key pair
            log.info("Generating {} key pair with key size {}", keyalg, keysize);
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(keyalg);
            keyGen.initialize(keysize, new SecureRandom());
            KeyPair keyPair = keyGen.generateKeyPair();

            // Determine signature algorithm
            String effectiveSigAlg = getEffectiveSigAlg(keyalg, sigalg);

            // Generate self-signed certificate
            X509Certificate cert = generateSelfSignedCertificate(keyPair, dname, validity, effectiveSigAlg, exts);

            log.info("Generated self-signed certificate for: {}", dname);

            // Load or create keystore
            KeyStore ks = loadOrCreateKeyStore(keystore, storetype, storepass);

            // Store key pair and certificate
            Certificate[] chain = new Certificate[] {cert};
            ks.setKeyEntry(alias, keyPair.getPrivate(), keypass, chain);

            log.info("Stored key pair with alias: {}", alias);

            // Save keystore
            saveKeyStore(ks, keystore, storepass);

            log.info("Key pair generation completed successfully");

        } catch (Exception e) {
            throw new MojoExecutionException("Failed to generate key pair", e);
        }
    }

    private static String getEffectiveSigAlg(String keyalg, String sigalg) {
        String effectiveSigAlg;
        if (sigalg != null) {
            effectiveSigAlg = sigalg;
        } else {
            // Default signature algorithms based on key algorithm
            if ("EC".equalsIgnoreCase(keyalg)) {
                effectiveSigAlg = "SHA256withECDSA";
            } else if ("DSA".equalsIgnoreCase(keyalg)) {
                effectiveSigAlg = "SHA256WithDSA";
            } else {
                effectiveSigAlg = "SHA256With" + keyalg.toUpperCase();
            }
        }
        return effectiveSigAlg;
    }

    /**
     * Generate certificate request (CSR).
     */
    public void generateCertificateRequest(
            File keystore,
            String storetype,
            char[] storepass,
            String alias,
            char[] keypass,
            String dname,
            String sigalg,
            File outputFile,
            List<String> exts)
            throws MojoExecutionException {

        try {
            java.security.Security.addProvider(new BouncyCastleProvider());

            // Load keystore
            KeyStore ks = loadKeyStore(keystore, storetype, storepass);

            // Get private key and certificate
            PrivateKey privateKey = (PrivateKey) ks.getKey(alias, keypass);
            if (privateKey == null) {
                throw new MojoExecutionException("Private key not found for alias: " + alias);
            }

            Certificate cert = ks.getCertificate(alias);
            if (cert == null) {
                throw new MojoExecutionException("Certificate not found for alias: " + alias);
            }

            PublicKey publicKey = cert.getPublicKey();

            // Determine subject DN
            X500Name subject;
            if (dname != null && !dname.isEmpty()) {
                X500Principal principal = new X500Principal(dname);
                subject = X500Name.getInstance(principal.getEncoded());
            } else if (cert instanceof X509Certificate) {
                subject = X500Name.getInstance(
                        ((X509Certificate) cert).getSubjectX500Principal().getEncoded());
            } else {
                throw new MojoExecutionException("DN not specified and cannot extract from certificate");
            }
            log.info("Subject Name in generateCertificateRequest(): {}", subject.toString());

            // Build CSR
            PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(subject, publicKey);

            // Add extensions if specified, otherwise copy from existing certificate
            if (exts != null && !exts.isEmpty()) {
                log.info("Adding {} extension(s) to certificate request", exts.size());
                org.bouncycastle.asn1.x509.ExtensionsGenerator extGen =
                        new org.bouncycastle.asn1.x509.ExtensionsGenerator();

                for (String ext : exts) {
                    log.info("Processing CSR extension: {}", ext);
                    addExtensionToGenerator(extGen, ext);
                }

                csrBuilder.addAttribute(
                        org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());
            } else if (cert instanceof X509Certificate) {
                // Copy extensions from existing certificate
                X509Certificate x509Cert = (X509Certificate) cert;
                copyExtensionsFromCertificate(csrBuilder, x509Cert);
            }

            // Sign the CSR
            String signatureAlg = sigalg != null ? sigalg : "SHA256WithRSA";
            ContentSigner signer = new JcaContentSignerBuilder(signatureAlg).build(privateKey);
            PKCS10CertificationRequest csr = csrBuilder.build(signer);

            log.info("Generated certificate request for: {}", subject);

            // Write CSR to file
            try (JcaPEMWriter pemWriter = new JcaPEMWriter(new FileWriter(outputFile))) {
                pemWriter.writeObject(csr);
            }

            log.info("Certificate request written to: {}", outputFile.getAbsolutePath());

        } catch (Exception e) {
            throw new MojoExecutionException("Failed to generate certificate request", e);
        }
    }

    /**
     * Generate certificate from a certificate request.
     */
    public void generateCertificate(
            File keystore,
            String storetype,
            char[] storepass,
            String alias,
            char[] keypass,
            File infile,
            File outfile,
            String dname,
            int validity,
            String sigalg,
            boolean rfc,
            List<String> exts)
            throws MojoExecutionException {

        try {
            java.security.Security.addProvider(new BouncyCastleProvider());

            // Load keystore
            KeyStore ks = loadKeyStore(keystore, storetype, storepass);

            // Get signing key
            PrivateKey signingKey = (PrivateKey) ks.getKey(alias, keypass);
            if (signingKey == null) {
                throw new MojoExecutionException("Signing key not found for alias: " + alias);
            }

            Certificate signerCert = ks.getCertificate(alias);
            if (signerCert == null) {
                throw new MojoExecutionException("Signer certificate not found for alias: " + alias);
            }

            // Read and parse CSR
            X500Name subject = null;
            PKCS10CertificationRequest csr = null;
            try (InputStream in = new FileInputStream(infile);
                    PEMParser pemParser = new PEMParser(new java.io.InputStreamReader(in))) {
                Object obj = pemParser.readObject();
                if (obj instanceof PKCS10CertificationRequest) {
                    csr = (PKCS10CertificationRequest) obj;
                    subject = csr.getSubject();
                    dname = subject.toString();
                    log.info("DName from CSR: {}", dname);
                } else {
                    throw new MojoExecutionException("Input file is not a valid CSR");
                }
            }
            log.info("DName: {}", dname);

            X500Name issuer = X500Name.getInstance(
                    ((X509Certificate) signerCert).getSubjectX500Principal().getEncoded());
            log.info("Issuer X500Name: {}", issuer.toString());

            BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
            Date notBefore = new Date();
            Date notAfter = new Date(notBefore.getTime() + ((long) validity * 24 * 60 * 60 * 1000));

            // Get public key from CSR
            org.bouncycastle.asn1.x509.SubjectPublicKeyInfo publicKeyInfo = csr.getSubjectPublicKeyInfo();
            org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter converter =
                    new org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter().setProvider("BC");
            PublicKey publicKey = converter.getPublicKey(publicKeyInfo);

            X509v3CertificateBuilder certBuilder =
                    new JcaX509v3CertificateBuilder(issuer, serial, notBefore, notAfter, subject, publicKey);

            // Copy extensions from CSR (if present)
            org.bouncycastle.asn1.pkcs.Attribute[] attributes =
                    csr.getAttributes(org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
            if (attributes != null && attributes.length > 0) {
                org.bouncycastle.asn1.x509.Extensions extensions = org.bouncycastle.asn1.x509.Extensions.getInstance(
                        attributes[0].getAttrValues().getObjectAt(0));

                for (org.bouncycastle.asn1.ASN1ObjectIdentifier oid : extensions.getExtensionOIDs()) {
                    org.bouncycastle.asn1.x509.Extension ext = extensions.getExtension(oid);
                    certBuilder.addExtension(oid, ext.isCritical(), ext.getParsedValue());
                    log.info("Copied extension from CSR: {} (critical={})", oid, ext.isCritical());
                }
            }

            // Add additional extensions from command line if specified (these override CSR extensions)
            if (exts != null && !exts.isEmpty()) {
                log.info("Adding {} additional extension(s) from command line", exts.size());
                for (String ext : exts) {
                    log.info("Adding additional extension: {}", ext);
                    parseAndAddExtension(certBuilder, ext);
                }
            }

            String signatureAlg = sigalg != null ? sigalg : "SHA256WithRSA";
            ContentSigner signer = new JcaContentSignerBuilder(signatureAlg).build(signingKey);

            X509CertificateHolder certHolder = certBuilder.build(signer);
            X509Certificate certificate =
                    new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);

            log.info("Generated certificate for: {}", subject);

            // Write certificate to file
            if (rfc) {
                try (JcaPEMWriter pemWriter = new JcaPEMWriter(new FileWriter(outfile))) {
                    pemWriter.writeObject(certificate);
                }
            } else {
                try (FileOutputStream fos = new FileOutputStream(outfile)) {
                    fos.write(certificate.getEncoded());
                }
            }

            log.info("Certificate written to: {}", outfile.getAbsolutePath());

        } catch (Exception e) {
            throw new MojoExecutionException("Failed to generate certificate", e);
        }
    }

    private X509Certificate generateSelfSignedCertificate(
            KeyPair keyPair, String dnName, int validity, String signatureAlgorithm, List<String> exts)
            throws Exception {

        X500Principal principal = new X500Principal(dnName);
        X500Name issuer = X500Name.getInstance(principal.getEncoded());
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + ((long) validity * 24 * 60 * 60 * 1000));

        X509v3CertificateBuilder certBuilder =
                new JcaX509v3CertificateBuilder(issuer, serial, notBefore, notAfter, issuer, keyPair.getPublic());

        // Add extensions if specified
        if (exts != null && !exts.isEmpty()) {
            for (String ext : exts) {
                log.info("Processing extension: {}", ext);
                // Extension parsing logic would go here
                // For example: SAN, KeyUsage, etc.
                parseAndAddExtension(certBuilder, ext);
                log.info("Parsed and added extension: {}", ext);
            }
        }

        ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm).build(keyPair.getPrivate());

        X509CertificateHolder certHolder = certBuilder.build(signer);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
    }

    private KeyStore loadOrCreateKeyStore(File keystoreFile, String storeType, char[] storePassword) throws Exception {
        String effectiveStoreType = storeType != null ? storeType : KeyStore.getDefaultType();
        KeyStore ks = KeyStore.getInstance(effectiveStoreType);

        if (keystoreFile != null && keystoreFile.exists()) {
            log.info("Loading existing keystore: {}", keystoreFile.getAbsolutePath());
            try (FileInputStream fis = new FileInputStream(keystoreFile)) {
                ks.load(fis, storePassword);
            }
        } else {
            log.info("Creating new keystore");
            ks.load(null, storePassword);

            if (keystoreFile != null && keystoreFile.getParentFile() != null) {
                keystoreFile.getParentFile().mkdirs();
            }
        }

        return ks;
    }

    private KeyStore loadKeyStore(File keystoreFile, String storeType, char[] storePassword) throws Exception {
        String effectiveStoreType = storeType != null ? storeType : KeyStore.getDefaultType();
        KeyStore ks = KeyStore.getInstance(effectiveStoreType);

        if (keystoreFile == null || !keystoreFile.exists()) {
            throw new MojoExecutionException("Keystore file not found: " + keystoreFile);
        }

        log.info("Loading keystore: {}", keystoreFile.getAbsolutePath());
        try (FileInputStream fis = new FileInputStream(keystoreFile)) {
            ks.load(fis, storePassword);
        }

        return ks;
    }

    private void saveKeyStore(KeyStore ks, File keystoreFile, char[] storePassword) throws Exception {
        if (keystoreFile == null) {
            throw new IllegalArgumentException("Keystore file cannot be null");
        }

        log.info("Saving keystore to: {}", keystoreFile.getAbsolutePath());
        try (FileOutputStream fos = new FileOutputStream(keystoreFile)) {
            ks.store(fos, storePassword);
        }
    }

    private void parseAndAddExtension(X509v3CertificateBuilder certBuilder, String extStr) throws Exception {
        // First check for '=' which is used in formats like "IssuerAlternativeName=DNS:value"
        int equalsIndex = extStr.indexOf('=');
        // Also check for ':' which is used in formats like "bc:c=ca:true"
        int colonIndex = extStr.indexOf(':');

        String extType;
        String extValue;

        // Determine which delimiter comes first
        if (equalsIndex != -1 && (colonIndex == -1 || equalsIndex < colonIndex)) {
            // Format: "extensionName=value" (e.g., "IssuerAlternativeName=DNS:...")
            extType = extStr.substring(0, equalsIndex).trim().toLowerCase();
            extValue = extStr.substring(equalsIndex + 1).trim();
        } else if (colonIndex != -1) {
            // Format: "extensionName:segment=value" (e.g., "bc:c=ca:true")
            extType = extStr.substring(0, colonIndex).trim().toLowerCase();
            String remaining = extStr.substring(colonIndex + 1).trim();

            int nextEqualsIndex = remaining.indexOf('=');
            if (nextEqualsIndex != -1) {
                // Skip the segment between ':' and '=' (like 'c' in 'bc:c=...')
                extValue = remaining.substring(nextEqualsIndex + 1).trim();
            } else {
                extValue = remaining;
            }
        } else {
            log.warn("Invalid extension format: {}", extStr);
            return;
        }

        switch (extType) {
            case "san":
            case "subjectalternativename":
                addSubjectAlternativeName(certBuilder, extValue);
                break;
            case "ian":
            case "issueralternativename":
                addIssuerAlternativeName(certBuilder, extValue);
                break;
            case "bc":
                addBasicConstraints(certBuilder, extValue);
                break;
            case "ku":
            case "keyusage":
                addKeyUsage(certBuilder, extValue);
                break;
            default:
                log.warn("Unsupported extension type: {}", extType);
        }
    }

    private void addSubjectAlternativeName(X509v3CertificateBuilder certBuilder, String value) throws Exception {
        String[] names = value.split(",");
        GeneralName[] generalNames = new GeneralName[names.length];

        for (int i = 0; i < names.length; i++) {
            String[] nameParts = names[i].trim().split(":", 2);
            if (nameParts.length != 2) {
                log.warn("Invalid SAN format: {}", names[i]);
                continue;
            }

            String type = nameParts[0].trim().toLowerCase();
            String nameValue = nameParts[1].trim();

            switch (type) {
                case "dns":
                    generalNames[i] = new GeneralName(GeneralName.dNSName, nameValue);
                    break;
                case "ip":
                    generalNames[i] = new GeneralName(GeneralName.iPAddress, nameValue);
                    break;
                case "email":
                    generalNames[i] = new GeneralName(GeneralName.rfc822Name, nameValue);
                    break;
                case "uri":
                    generalNames[i] = new GeneralName(GeneralName.uniformResourceIdentifier, nameValue);
                    break;
                default:
                    log.warn("Unsupported SAN type: {}", type);
            }
        }

        GeneralNames subjectAltNames = new GeneralNames(generalNames);
        certBuilder.addExtension(Extension.subjectAlternativeName, false, subjectAltNames);
        log.info("Added Subject Alternative Name extension");
    }

    private void addIssuerAlternativeName(X509v3CertificateBuilder certBuilder, String value) throws Exception {
        String[] names = value.split(",");
        GeneralName[] generalNames = new GeneralName[names.length];

        for (int i = 0; i < names.length; i++) {
            String[] nameParts = names[i].trim().split(":", 2);
            if (nameParts.length != 2) {
                log.warn("Invalid IAN format: {}", names[i]);
                continue;
            }

            String type = nameParts[0].trim().toLowerCase();
            String nameValue = nameParts[1].trim();

            switch (type) {
                case "dns":
                    generalNames[i] = new GeneralName(GeneralName.dNSName, nameValue);
                    break;
                case "ip":
                    generalNames[i] = new GeneralName(GeneralName.iPAddress, nameValue);
                    break;
                case "email":
                    generalNames[i] = new GeneralName(GeneralName.rfc822Name, nameValue);
                    break;
                case "uri":
                    generalNames[i] = new GeneralName(GeneralName.uniformResourceIdentifier, nameValue);
                    break;
                default:
                    log.warn("Unsupported IAN type: {}", type);
            }
        }

        GeneralNames issuerAltNames = new GeneralNames(generalNames);
        certBuilder.addExtension(Extension.issuerAlternativeName, false, issuerAltNames);
        log.info("Added Issuer Alternative Name extension");
    }

    private void addBasicConstraints(X509v3CertificateBuilder certBuilder, String value) throws Exception {
        boolean isCa = false;
        int pathLen = -1;

        String[] parts = value.split(",");
        for (String part : parts) {
            String[] kv = part.trim().split(":");
            if (kv.length == 2) {
                String key = kv[0].trim().toLowerCase();
                String val = kv[1].trim();

                if ("ca".equals(key)) {
                    isCa = Boolean.parseBoolean(val);
                } else if ("pathlen".equals(key)) {
                    pathLen = Integer.parseInt(val);
                }
            }
        }

        BasicConstraints basicConstraints = pathLen >= 0 ? new BasicConstraints(pathLen) : new BasicConstraints(isCa);

        certBuilder.addExtension(Extension.basicConstraints, true, basicConstraints);
        log.info("Added Basic Constraints extension: CA={}, pathLen={}", isCa, pathLen);
    }

    private void addKeyUsage(X509v3CertificateBuilder certBuilder, String value) throws Exception {
        int usage = 0;
        String[] usages = value.split(",");

        for (String u : usages) {
            String usageType = u.trim().toLowerCase();
            switch (usageType) {
                case "digitalsignature":
                    usage |= KeyUsage.digitalSignature;
                    break;
                case "nonrepudiation":
                    usage |= KeyUsage.nonRepudiation;
                    break;
                case "keyencipherment":
                    usage |= KeyUsage.keyEncipherment;
                    break;
                case "dataencipherment":
                    usage |= KeyUsage.dataEncipherment;
                    break;
                case "keyagreement":
                    usage |= KeyUsage.keyAgreement;
                    break;
                case "keycertsign":
                    usage |= KeyUsage.keyCertSign;
                    break;
                case "crlsign":
                    usage |= KeyUsage.cRLSign;
                    break;
                case "encipheronly":
                    usage |= KeyUsage.encipherOnly;
                    break;
                case "decipheronly":
                    usage |= KeyUsage.decipherOnly;
                    break;
                default:
                    log.warn("Unknown key usage: {}", usageType);
            }
        }

        if (usage != 0) {
            certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(usage));
            log.info("Added Key Usage extension: {}", value);
        }
    }

    private void copyExtensionsFromCertificate(PKCS10CertificationRequestBuilder csrBuilder, X509Certificate cert)
            throws Exception {

        java.util.Set<String> criticalOIDs = cert.getCriticalExtensionOIDs();
        java.util.Set<String> nonCriticalOIDs = cert.getNonCriticalExtensionOIDs();

        if ((criticalOIDs == null || criticalOIDs.isEmpty())
                && (nonCriticalOIDs == null || nonCriticalOIDs.isEmpty())) {
            log.info("No extensions found in existing certificate to copy");
            return;
        }

        org.bouncycastle.asn1.x509.ExtensionsGenerator extGen = new org.bouncycastle.asn1.x509.ExtensionsGenerator();
        int extensionCount = 0;

        // Copy critical extensions
        if (criticalOIDs != null) {
            for (String oidStr : criticalOIDs) {
                byte[] extValue = cert.getExtensionValue(oidStr);
                if (extValue != null) {
                    org.bouncycastle.asn1.ASN1ObjectIdentifier oid =
                            new org.bouncycastle.asn1.ASN1ObjectIdentifier(oidStr);
                    org.bouncycastle.asn1.ASN1OctetString oct =
                            org.bouncycastle.asn1.ASN1OctetString.getInstance(extValue);
                    extGen.addExtension(oid, true, org.bouncycastle.asn1.ASN1Primitive.fromByteArray(oct.getOctets()));
                    log.info("Copied critical extension: {}", oidStr);
                    extensionCount++;
                }
            }
        }

        // Copy non-critical extensions
        if (nonCriticalOIDs != null) {
            for (String oidStr : nonCriticalOIDs) {
                byte[] extValue = cert.getExtensionValue(oidStr);
                if (extValue != null) {
                    org.bouncycastle.asn1.ASN1ObjectIdentifier oid =
                            new org.bouncycastle.asn1.ASN1ObjectIdentifier(oidStr);
                    org.bouncycastle.asn1.ASN1OctetString oct =
                            org.bouncycastle.asn1.ASN1OctetString.getInstance(extValue);
                    extGen.addExtension(oid, false, org.bouncycastle.asn1.ASN1Primitive.fromByteArray(oct.getOctets()));
                    log.info("Copied non-critical extension: {}", oidStr);
                    extensionCount++;
                }
            }
        }

        if (extensionCount > 0) {
            csrBuilder.addAttribute(
                    org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());
            log.info("Copied {} extension(s) from existing certificate to CSR", extensionCount);
        }
    }

    private void addExtensionToGenerator(org.bouncycastle.asn1.x509.ExtensionsGenerator extGen, String extStr)
            throws Exception {
        // Parse extension string using existing logic
        int equalsIndex = extStr.indexOf('=');
        int colonIndex = extStr.indexOf(':');

        String extType;
        String extValue;

        if (equalsIndex != -1 && (colonIndex == -1 || equalsIndex < colonIndex)) {
            extType = extStr.substring(0, equalsIndex).trim().toLowerCase();
            extValue = extStr.substring(equalsIndex + 1).trim();
        } else if (colonIndex != -1) {
            extType = extStr.substring(0, colonIndex).trim().toLowerCase();
            String remaining = extStr.substring(colonIndex + 1).trim();
            int nextEqualsIndex = remaining.indexOf('=');
            extValue = nextEqualsIndex != -1
                    ? remaining.substring(nextEqualsIndex + 1).trim()
                    : remaining;
        } else {
            log.warn("Invalid extension format: {}", extStr);
            return;
        }

        // Create extension based on type
        switch (extType) {
            case "san":
            case "subjectalternativename":
                extGen.addExtension(Extension.subjectAlternativeName, false, createGeneralNames(extValue));
                log.info("Added SAN extension to generator");
                break;
            case "ian":
            case "issueralternativename":
                extGen.addExtension(Extension.issuerAlternativeName, false, createGeneralNames(extValue));
                log.info("Added IAN extension to generator");
                break;
            case "bc":
                extGen.addExtension(Extension.basicConstraints, true, createBasicConstraints(extValue));
                log.info("Added Basic Constraints extension to generator");
                break;
            case "ku":
            case "keyusage":
                extGen.addExtension(Extension.keyUsage, true, createKeyUsage(extValue));
                log.info("Added Key Usage extension to generator");
                break;
            default:
                log.warn("Unsupported extension type: {}", extType);
        }
    }

    private GeneralNames createGeneralNames(String value) {
        String[] names = value.split(",");
        GeneralName[] generalNames = new GeneralName[names.length];

        for (int i = 0; i < names.length; i++) {
            String[] nameParts = names[i].trim().split(":", 2);
            if (nameParts.length == 2) {
                String type = nameParts[0].trim().toLowerCase();
                String nameValue = nameParts[1].trim();

                switch (type) {
                    case "dns":
                        generalNames[i] = new GeneralName(GeneralName.dNSName, nameValue);
                        break;
                    case "ip":
                        generalNames[i] = new GeneralName(GeneralName.iPAddress, nameValue);
                        break;
                    case "email":
                        generalNames[i] = new GeneralName(GeneralName.rfc822Name, nameValue);
                        break;
                    case "uri":
                        generalNames[i] = new GeneralName(GeneralName.uniformResourceIdentifier, nameValue);
                        break;
                }
            }
        }

        return new GeneralNames(generalNames);
    }

    private BasicConstraints createBasicConstraints(String value) {
        boolean isCa = false;
        int pathLen = -1;

        String[] parts = value.split(",");
        for (String part : parts) {
            String[] kv = part.trim().split(":");
            if (kv.length == 2) {
                String key = kv[0].trim().toLowerCase();
                String val = kv[1].trim();

                if ("ca".equals(key)) {
                    isCa = Boolean.parseBoolean(val);
                } else if ("pathlen".equals(key)) {
                    pathLen = Integer.parseInt(val);
                }
            }
        }

        return pathLen >= 0 ? new BasicConstraints(pathLen) : new BasicConstraints(isCa);
    }

    private KeyUsage createKeyUsage(String value) {
        int usage = 0;
        String[] usages = value.split(",");

        for (String u : usages) {
            String usageType = u.trim().toLowerCase();
            switch (usageType) {
                case "digitalsignature":
                    usage |= KeyUsage.digitalSignature;
                    break;
                case "nonrepudiation":
                    usage |= KeyUsage.nonRepudiation;
                    break;
                case "keyencipherment":
                    usage |= KeyUsage.keyEncipherment;
                    break;
                case "keycertsign":
                    usage |= KeyUsage.keyCertSign;
                    break;
                // Add other key usages as needed
            }
        }

        return new KeyUsage(usage);
    }
}
