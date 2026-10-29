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
import de.rwth.idsg.steve.service.dto.AuthTagContext;
import de.rwth.idsg.steve.utils.CertificateUtils;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import tools.jackson.databind.JsonNode;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/** Explicit lab policy: pinned contract certificates and operator-managed revocation.
 * The MO issuer is independent of the V2G/SECC issuer and native OCPP trust.
 * This is not a roaming contract or production revocation provider.
 */
@Service
public class PncContractService {
    private record Contract(String token, X509Certificate certificate, boolean revoked) { }
    private final Map<String, Contract> contracts = new LinkedHashMap<>();
    private final X509Certificate issuer;
    private final PrivateKey key;
    private final OcppTagService tags;

    public PncContractService(@Value("${steve.pnc.lab-contracts:}") String registry,
                              @Value("${steve.pnc.mo-ca-certificate:}") String certificate,
                              @Value("${steve.pnc.mo-ca-key:}") String privateKey,
                              OcppTagService tags) throws Exception {
        this.tags = tags;
        if (registry.isBlank() && certificate.isBlank() && privateKey.isBlank()) { issuer = null; key = null; return; }
        issuer = CertificateUtils.parseCertificate(Files.readString(Path.of(certificate)));
        key = CertificateUtils.parsePrivateKeyViaBouncyCastle(Files.readString(Path.of(privateKey)), null);
        issuer.checkValidity();
        if (issuer.getBasicConstraints() < 0 || issuer.getKeyUsage() == null || !issuer.getKeyUsage()[5]) {
            throw new IllegalArgumentException("Lab MO issuer must be a signing CA");
        }
        if (Files.size(Path.of(registry)) > 524288) { throw new IllegalArgumentException("Lab registry is too large"); }
        var entries = PncProtocol.JSON.readTree(Files.readString(Path.of(registry)));
        if (!entries.isArray() || entries.size() > 64) { throw new IllegalArgumentException("Invalid lab registry"); }
        for (var entry : entries) {
            var token = PncProtocol.text(entry, "idToken", 20);
            var cert = CertificateUtils.parseCertificate(PncProtocol.text(entry, "certificate", 5500));
            cert.verify(issuer.getPublicKey());
            if (!cert.getIssuerX500Principal().equals(issuer.getSubjectX500Principal()) || cert.getBasicConstraints() >= 0) {
                throw new IllegalArgumentException("Lab contract must be a leaf of the configured MO issuer");
            }
            if (cert.getKeyUsage() == null || !cert.getKeyUsage()[0]
                || (cert.getExtendedKeyUsage() != null && (cert.getExtendedKeyUsage().contains("1.3.6.1.5.5.7.3.1")
                    || cert.getExtendedKeyUsage().contains("1.3.6.1.5.5.7.3.2")))) {
                throw new IllegalArgumentException("Lab contract requires digital signature use, without TLS identity purposes");
            }
            var status = PncProtocol.text(entry, "status", 10);
            if (!status.equals("Good") && !status.equals("Revoked")) { throw new IllegalArgumentException("Invalid lab status"); }
            if (contracts.putIfAbsent(token.toUpperCase(Locale.ROOT), new Contract(token, cert, status.equals("Revoked"))) != null) {
                throw new IllegalArgumentException("Duplicate lab eMAID");
            }
        }
        // Validate the private/public key match by building and verifying a real signed response.
        if (!contracts.isEmpty()) {
            var first = contracts.values().iterator().next();
            var id = id(first, "SHA256");
            var ocsp = new org.bouncycastle.cert.ocsp.OCSPResp(Base64.getDecoder().decode(response(first, id)));
            var basic = (org.bouncycastle.cert.ocsp.BasicOCSPResp) ocsp.getResponseObject();
            if (!basic.isSignatureValid(new org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder().build(issuer.getPublicKey()))) {
                throw new IllegalArgumentException("Lab MO key mismatch");
            }
        }
    }

    public boolean available() { return issuer != null; }

    public String publicRoot() throws Exception {
        return issuer == null ? null : CertificateUtils.certificatesToPEM(java.util.List.of(issuer));
    }

    public String authorize(JsonNode request, String station) {
        if (!available()) { return denied("NoCertificateAvailable"); }
        try {
            issuer.checkValidity();
            var token = PncProtocol.text(request.get("idToken"), "idToken", 20);
            var contract = contracts.get(token.toUpperCase(Locale.ROOT));
            if (contract == null) { return denied("ContractCancelled"); }
            if (contract.revoked()) { return denied("CertificateRevoked"); }
            try { contract.certificate().checkValidity(); }
            catch (java.security.cert.CertificateExpiredException e) { return denied("CertificateExpired"); }
            boolean evidence = false;
            if (request.has("certificate")) {
                var presented = CertificateUtils.parseCertificates(request.get("certificate").asString());
                if (presented.isEmpty() || presented.size() > 2 || !presented.getFirst().equals(contract.certificate())) {
                    return denied("CertChainError");
                }
                if (presented.size() == 2 && !presented.get(1).equals(issuer)) { return denied("CertChainError"); }
                evidence = true;
            }
            if (request.has("iso15118CertificateHashData")) {
                var hashes = request.get("iso15118CertificateHashData");
                if (hashes.size() != 1 || !matches(contract, hashes.get(0))) { return denied("CertChainError"); }
                evidence = true;
            }
            if (!evidence) { return denied("NoCertificateAvailable"); }
            var tag = tags.getIdTagInfo(token, AuthTagContext.StationAuth, station, null);
            var info = PncProtocol.JSON.createObjectNode().put("status", tag.getStatus().value());
            var expiry = Instant.now().plusSeconds(300);
            if (expiry.isAfter(contract.certificate().getNotAfter().toInstant())) { expiry = contract.certificate().getNotAfter().toInstant(); }
            if (tag.getExpiryDate() != null && expiry.isAfter(Instant.ofEpochMilli(tag.getExpiryDate().getMillis()))) {
                expiry = Instant.ofEpochMilli(tag.getExpiryDate().getMillis());
            }
            info.put("cacheExpiryDateTime", expiry.toString());
            var result = PncProtocol.JSON.createObjectNode().put("certificateStatus", "Accepted");
            result.set("idTokenInfo", info);
            return PncProtocol.JSON.writeValueAsString(result);
        } catch (Exception ignored) { return denied("CertChainError"); }
    }

    public String certificateStatus(JsonNode request) {
        if (!available()) { return "{\"status\":\"Failed\"}"; }
        try {
            issuer.checkValidity();
            var hash = request.get("ocspRequestData");
            // Deliberately never fetch station-supplied responderURL. Only this lab issuer is served.
            for (var contract : contracts.values()) {
                if (matches(contract, hash)) {
                    return PncProtocol.JSON.writeValueAsString(Map.of("status", "Accepted", "ocspResult",
                        response(contract, id(contract, hash.get("hashAlgorithm").asString()))));
                }
            }
        } catch (Exception ignored) { /* No synthetic success for an unknown or invalid issuer. */ }
        return "{\"status\":\"Failed\"}";
    }

    private boolean matches(Contract contract, JsonNode hash) throws Exception {
        var id = id(contract, hash.get("hashAlgorithm").asString());
        var hex = HexFormat.of();
        return id.getSerialNumber().equals(new java.math.BigInteger(hash.get("serialNumber").asString(), 16))
            && java.security.MessageDigest.isEqual(id.getIssuerNameHash(), hex.parseHex(hash.get("issuerNameHash").asString()))
            && java.security.MessageDigest.isEqual(id.getIssuerKeyHash(), hex.parseHex(hash.get("issuerKeyHash").asString()));
    }

    private CertificateID id(Contract contract, String hashAlgorithm) throws Exception {
        var oid = switch (hashAlgorithm) {
            case "SHA256" -> NISTObjectIdentifiers.id_sha256;
            case "SHA384" -> NISTObjectIdentifiers.id_sha384;
            case "SHA512" -> NISTObjectIdentifiers.id_sha512;
            default -> throw new IllegalArgumentException("Unsupported digest");
        };
        var calculator = new JcaDigestCalculatorProviderBuilder().build().get(new AlgorithmIdentifier(oid));
        return new CertificateID(calculator, new JcaX509CertificateHolder(issuer), contract.certificate().getSerialNumber());
    }

    private String response(Contract contract, CertificateID id) throws Exception {
        var now = Instant.now();
        var builder = new BasicOCSPRespBuilder(new RespID(new JcaX509CertificateHolder(issuer).getSubject()));
        var status = contract.revoked() ? new RevokedStatus(Date.from(now.minusSeconds(60)), 0) : CertificateStatus.GOOD;
        builder.addResponse(id, status, Date.from(now), Date.from(now.plusSeconds(300)), null);
        var basic = builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(key),
            new X509CertificateHolder[]{new JcaX509CertificateHolder(issuer)}, Date.from(now));
        var result = Base64.getEncoder().encodeToString(new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basic).getEncoded());
        if (result.length() > 5500) { throw new IllegalStateException("OCSP response too large"); }
        return result;
    }

    private static String denied(String status) {
        return PncProtocol.JSON.writeValueAsString(Map.of("idTokenInfo", Map.of("status", "Invalid"), "certificateStatus", status));
    }
}
