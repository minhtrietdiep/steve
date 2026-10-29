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
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

class PncCryptoTest {
    @TempDir Path directory;

    static String pem(Object object) throws Exception {
        var s = new StringWriter();
        try (var w = new JcaPEMWriter(s)) {
            if (object instanceof java.security.PrivateKey key) {
                // Preserve named-curve parameters in the PKCS#8 algorithm identifier.
                w.writeObject(new org.bouncycastle.util.io.pem.PemObject("PRIVATE KEY", key.getEncoded()));
            } else { w.writeObject(object); }
        }
        return s.toString();
    }

    @Test
    void issuesRealV2gServerCertificateAndVerifiesChain() throws Exception {
        var generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        var caKey = generator.generateKeyPair();
        var subject = new X500Name("CN=Ephemeral V2G Test Root,O=SteVe Lab");
        var builder = new JcaX509v3CertificateBuilder(subject, BigInteger.ONE,
            Date.from(Instant.now().minusSeconds(120)), Date.from(Instant.now().plusSeconds(86400)), subject, caKey.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        var ca = new JcaX509CertificateConverter().getCertificate(builder.build(
            new JcaContentSignerBuilder("SHA256withECDSA").build(caKey.getPrivate())));
        var certFile = directory.resolve("ca.pem"); var keyFile = directory.resolve("ca-key.pem");
        Files.writeString(certFile, pem(ca)); Files.writeString(keyFile, pem(caKey.getPrivate()));
        var signer = new PncV2gSigner(certFile.toString(), keyFile.toString());
        var scalar = ((java.security.interfaces.ECPrivateKey) caKey.getPrivate()).getS();
        var sec1 = new org.bouncycastle.asn1.sec.ECPrivateKey(256, scalar, org.bouncycastle.asn1.sec.SECObjectIdentifiers.secp256r1);
        var sec1Pem = pem(new org.bouncycastle.util.io.pem.PemObject("EC PRIVATE KEY", sec1.getEncoded()));
        assertNotNull(CertificateUtils.parsePrivateKeyViaBouncyCastle(sec1Pem, null));
        var leafKey = generator.generateKeyPair();
        var request = new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=DE*LAB*E12345,O=SteVe Lab"), leafKey.getPublic())
            .build(new JcaContentSignerBuilder("SHA256withECDSA").build(leafKey.getPrivate()));
        var validated = signer.validate(pem(request));
        var chain = CertificateUtils.parseCertificates(signer.sign(validated));
        assertEquals(2, chain.size());
        chain.getFirst().verify(ca.getPublicKey());
        chain.getFirst().checkValidity();
        assertArrayEquals(leafKey.getPublic().getEncoded(), chain.getFirst().getPublicKey().getEncoded());
        assertEquals(-1, chain.getFirst().getBasicConstraints());
        assertTrue(chain.getFirst().getExtendedKeyUsage().contains("1.3.6.1.5.5.7.3.1"));
        assertFalse(chain.getFirst().getExtendedKeyUsage().contains("1.3.6.1.5.5.7.3.2"));
        assertFalse(chain.getFirst().getNotAfter().after(ca.getNotAfter()));
        assertNotEquals(chain.getFirst().getSerialNumber(), CertificateUtils.parseCertificates(signer.sign(validated)).getFirst().getSerialNumber());

        var badRequest = new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=Invalid"), leafKey.getPublic())
            .build(new JcaContentSignerBuilder("SHA256withECDSA").build(caKey.getPrivate()));
        assertThrows(Exception.class, () -> signer.validate(pem(badRequest)));
        generator.initialize(new ECGenParameterSpec("secp384r1"));
        var wrongCurve = generator.generateKeyPair();
        var wrongRequest = new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=Invalid"), wrongCurve.getPublic())
            .build(new JcaContentSignerBuilder("SHA384withECDSA").build(wrongCurve.getPrivate()));
        assertThrows(Exception.class, () -> signer.validate(pem(wrongRequest)));
        Files.writeString(keyFile, pem(leafKey.getPrivate()));
        assertThrows(Exception.class, () -> new PncV2gSigner(certFile.toString(), keyFile.toString()));
    }

    @Test
    void signerIsUnavailableWithoutExplicitConfiguration() throws Exception {
        var signer = new PncV2gSigner("", "");
        assertFalse(signer.available());
        assertThrows(Exception.class, () -> signer.validate("invalid"));
    }
}
