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

import de.rwth.idsg.steve.service.OcppTagService;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import ocpp.cs._2015._10.AuthorizationStatus;
import ocpp.cs._2015._10.IdTagInfo;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class PncContractTest {
    @TempDir Path directory;

    @Test
    void validatesPinnedContractAndProducesSignedOcspWithRevocation() throws Exception {
        var generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        var caKey = generator.generateKeyPair();
        var name = new X500Name("CN=Ephemeral MO Test Root");
        var from = Date.from(Instant.now().minusSeconds(60));
        var to = Date.from(Instant.now().plusSeconds(86400));
        var caBuilder = new JcaX509v3CertificateBuilder(name, BigInteger.ONE, from, to, name, caKey.getPublic());
        caBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        caBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        var ca = new JcaX509CertificateConverter().getCertificate(caBuilder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(caKey.getPrivate())));
        var leafBuilder = new JcaX509v3CertificateBuilder(name, BigInteger.TEN, from, to, new X500Name("CN=DELAB123"), generator.generateKeyPair().getPublic());
        leafBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        leafBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        var leaf = new JcaX509CertificateConverter().getCertificate(leafBuilder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(caKey.getPrivate())));
        var certPath = directory.resolve("mo.pem"); var keyPath = directory.resolve("mo-key.pem"); var registry = directory.resolve("contracts.json");
        Files.writeString(certPath, PncCryptoTest.pem(ca)); Files.writeString(keyPath, PncCryptoTest.pem(caKey.getPrivate()));
        Files.writeString(registry, PncProtocol.JSON.writeValueAsString(List.of(Map.of("idToken", "DELAB123", "certificate", PncCryptoTest.pem(leaf), "status", "Good"))));
        var tags = mock(OcppTagService.class);
        when(tags.getIdTagInfo(anyString(), any(), anyString(), isNull())).thenReturn(new IdTagInfo().withStatus(AuthorizationStatus.ACCEPTED));
        var service = new PncContractService(registry.toString(), certPath.toString(), keyPath.toString(), tags);
        var auth = PncProtocol.JSON.valueToTree(Map.of("idToken", Map.of("idToken", "DELAB123"), "certificate", PncCryptoTest.pem(leaf)));
        var response = PncProtocol.parse(service.authorize(auth, "station"));
        assertEquals("Accepted", response.get("certificateStatus").asString());
        assertEquals("Accepted", response.get("idTokenInfo").get("status").asString());
        when(tags.getIdTagInfo(anyString(), any(), anyString(), isNull())).thenReturn(new IdTagInfo().withStatus(AuthorizationStatus.BLOCKED));
        assertEquals("Blocked", PncProtocol.parse(service.authorize(auth, "station")).get("idTokenInfo").get("status").asString());
        var noEvidence = PncProtocol.JSON.valueToTree(Map.of("idToken", Map.of("idToken", "DELAB123")));
        assertEquals("Invalid", PncProtocol.parse(service.authorize(noEvidence, "station")).get("idTokenInfo").get("status").asString());
        for (var algorithm : List.of("SHA256", "SHA384", "SHA512")) {
            var oid = algorithm.equals("SHA256") ? NISTObjectIdentifiers.id_sha256 : algorithm.equals("SHA384") ? NISTObjectIdentifiers.id_sha384 : NISTObjectIdentifiers.id_sha512;
            var id = new CertificateID(new JcaDigestCalculatorProviderBuilder().build().get(new AlgorithmIdentifier(oid)), new JcaX509CertificateHolder(ca), leaf.getSerialNumber());
            var hash = Map.of("hashAlgorithm", algorithm, "issuerNameHash", HexFormat.of().formatHex(id.getIssuerNameHash()),
                "issuerKeyHash", HexFormat.of().formatHex(id.getIssuerKeyHash()), "serialNumber", "0a", "responderURL", "http://127.0.0.1:1/never-fetch");
            var request = PncProtocol.JSON.valueToTree(Map.of("ocspRequestData", hash));
            var status = PncProtocol.parse(service.certificateStatus(request));
            assertEquals("Accepted", status.get("status").asString());
            var ocsp = (BasicOCSPResp) new OCSPResp(Base64.getDecoder().decode(status.get("ocspResult").asString())).getResponseObject();
            assertTrue(ocsp.isSignatureValid(new JcaContentVerifierProviderBuilder().build(ca.getPublicKey())));
            assertNull(ocsp.getResponses()[0].getCertStatus());
            assertEquals(id, ocsp.getResponses()[0].getCertID());
            assertTrue(ocsp.getResponses()[0].getNextUpdate().after(new Date()));
        }
        Files.writeString(registry, PncProtocol.JSON.writeValueAsString(List.of(Map.of("idToken", "DELAB123", "certificate", PncCryptoTest.pem(leaf), "status", "Revoked"))));
        service = new PncContractService(registry.toString(), certPath.toString(), keyPath.toString(), tags);
        assertEquals("CertificateRevoked", PncProtocol.parse(service.authorize(auth, "station")).get("certificateStatus").asString());
    }

    @Test
    void noImplicitTrustWithoutConfiguration() throws Exception {
        var service = new PncContractService("", "", "", mock(OcppTagService.class));
        assertFalse(service.available());
        assertEquals("Failed", PncProtocol.parse(service.certificateStatus(PncProtocol.JSON.createObjectNode())).get("status").asString());
    }
}
