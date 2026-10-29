/*
 * SteVe - SteckdosenVerwaltung - https://github.com/steve-community/steve
 * Copyright (C) 2013-2026 SteVe Community Team
 * All Rights Reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package de.rwth.idsg.steve.service.pnc;

import de.rwth.idsg.steve.utils.CertificateUtils;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.AlgorithmParameters;
import java.security.spec.ECParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;

/** Isolated online lab V2G issuer. Never uses the OCPP client-certificate CA. */
@Service
public class PncV2gSigner {
    private final X509Certificate ca;
    private final PrivateKey key;
    private final SecureRandom random = new SecureRandom();

    public PncV2gSigner(@Value("${steve.pnc.ca-certificate:}") String certificate,
                        @Value("${steve.pnc.ca-key:}") String privateKey) throws Exception {
        if (certificate.isBlank() && privateKey.isBlank()) { ca = null; key = null; return; }
        ca = CertificateUtils.parseCertificate(Files.readString(Path.of(certificate)));
        key = CertificateUtils.parsePrivateKeyViaBouncyCastle(Files.readString(Path.of(privateKey)), null);
        ca.checkValidity();
        if (ca.getBasicConstraints() < 0 || ca.getKeyUsage() == null || !ca.getKeyUsage()[5]) {
            throw new IllegalArgumentException("PnC issuer must be a signing CA");
        }
        byte[] proof = new byte[32]; random.nextBytes(proof);
        var s = java.security.Signature.getInstance("SHA256withECDSA");
        s.initSign(key); s.update(proof); byte[] signature = s.sign();
        s.initVerify(ca.getPublicKey()); s.update(proof);
        if (!s.verify(signature)) { throw new IllegalArgumentException("PnC issuer key mismatch"); }
    }

    public boolean available() { return ca != null; }

    public String publicRoot() throws Exception {
        return ca == null ? null : CertificateUtils.certificatesToPEM(List.of(ca));
    }

    public PKCS10CertificationRequest validate(String pem) throws Exception {
        if (!available() || pem == null || pem.length() > 5500 || !pem.startsWith("-----BEGIN CERTIFICATE REQUEST-----")) {
            throw new IllegalArgumentException("V2G signing unavailable or CSR invalid");
        }
        ca.checkValidity();
        var csr = CertificateUtils.parseCsr(pem);
        var publicKey = new JcaPEMKeyConverter().getPublicKey(csr.getSubjectPublicKeyInfo());
        var parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("secp256r1"));
        var expected = parameters.getParameterSpec(ECParameterSpec.class);
        if (!(publicKey instanceof ECPublicKey ec) || !ec.getParams().getCurve().equals(expected.getCurve())
            || !ec.getParams().getGenerator().equals(expected.getGenerator())
            || !ec.getParams().getOrder().equals(expected.getOrder())
            || ec.getParams().getCofactor() != expected.getCofactor()
            || csr.getSubject().getRDNs().length == 0
            || !csr.isSignatureValid(new JcaContentVerifierProviderBuilder().build(publicKey))) {
            throw new IllegalArgumentException("V2G requires a valid P-256 CSR");
        }
        return csr;
    }

    public String sign(PKCS10CertificationRequest csr) throws Exception {
        ca.checkValidity();
        var now = Instant.now();
        var end = now.plus(90, ChronoUnit.DAYS);
        if (end.isAfter(ca.getNotAfter().toInstant())) { end = ca.getNotAfter().toInstant(); }
        var start = now.minusSeconds(60);
        if (start.isBefore(ca.getNotBefore().toInstant())) { start = ca.getNotBefore().toInstant(); }
        var b = new X509v3CertificateBuilder(new JcaX509CertificateHolder(ca).getSubject(),
            new BigInteger(159, random).add(BigInteger.ONE), Date.from(start), Date.from(end),
            csr.getSubject(), csr.getSubjectPublicKeyInfo());
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyAgreement));
        b.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
        var ext = new JcaX509ExtensionUtils();
        b.addExtension(Extension.subjectKeyIdentifier, false, ext.createSubjectKeyIdentifier(csr.getSubjectPublicKeyInfo()));
        b.addExtension(Extension.authorityKeyIdentifier, false, ext.createAuthorityKeyIdentifier(ca));
        var holder = b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(key));
        var leaf = new JcaX509CertificateConverter().getCertificate(holder);
        leaf.verify(ca.getPublicKey());
        var chain = CertificateUtils.certificatesToPEM(List.of(leaf, ca));
        if (chain.length() > 10000) { throw new IllegalStateException("V2G chain exceeds wire limit"); }
        return chain;
    }
}
