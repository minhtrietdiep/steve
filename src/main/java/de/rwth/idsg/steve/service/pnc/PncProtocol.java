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

import tools.jackson.core.json.JsonFactory;
import tools.jackson.core.StreamReadConstraints;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

import java.util.Base64;
import java.util.Set;

/** Detailed message definitions from OCA application note v1.0, sections 6–8. */
public final class PncProtocol {
    public static final String VENDOR = "org.openchargealliance.iso15118pnc";
    public static final int MAX_DATA = 32768;
    public static final Set<String> INBOUND = Set.of("SignCertificate", "Authorize", "GetCertificateStatus", "Get15118EVCertificate");
    public static final Set<String> OUTBOUND = Set.of("CertificateSigned", "DeleteCertificate", "GetInstalledCertificateIds", "InstallCertificate", "TriggerMessage");
    public static final Set<String> ROOT_TYPES = Set.of("V2GRootCertificate", "MORootCertificate");
    public static final Set<String> CERT_TYPES = Set.of("V2GRootCertificate", "MORootCertificate", "V2GCertificateChain");
    public static final JsonMapper JSON = JsonMapper.builder(JsonFactory.builder()
        .streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(12).maxStringLength(16384).build())
        .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).build())
        .enable(tools.jackson.databind.DeserializationFeature.FAIL_ON_TRAILING_TOKENS).build();

    private PncProtocol() { }

    public record SignCertificate(String csr) { }
    public record CertificateSigned(String certificateChain) { }
    public record Status(String status) { }
    public record IdToken(String idToken) { }

    public static ObjectNode parse(String data) {
        require(data != null && data.length() <= MAX_DATA);
        JsonNode node = JSON.readTree(data);
        require(node != null && node.isObject());
        return (ObjectNode) node;
    }

    public static ObjectNode request(String message, String data, boolean inbound) {
        require(message != null);
        require((inbound ? INBOUND : OUTBOUND).contains(message));
        var n = parse(data);
        switch (message) {
            case "SignCertificate" -> { fields(n, "csr"); text(n, "csr", 5500); }
            case "CertificateSigned" -> { fields(n, "certificateChain"); text(n, "certificateChain", 10000); }
            case "TriggerMessage" -> fields(n);
            case "InstallCertificate" -> {
                fields(n, "certificateType", "certificate");
                oneOf(text(n, "certificateType", 50), ROOT_TYPES);
                text(n, "certificate", 5500);
            }
            case "GetInstalledCertificateIds" -> {
                fields(n, "certificateType");
                if (n.has("certificateType")) {
                    var types = n.get("certificateType");
                    require(types.isArray() && types.size() <= 3);
                    for (var t : types) { require(t.isString()); oneOf(t.asString(), CERT_TYPES); }
                }
            }
            case "DeleteCertificate" -> { fields(n, "certificateHashData"); hash(n.get("certificateHashData"), false); }
            case "GetCertificateStatus" -> { fields(n, "ocspRequestData"); hash(n.get("ocspRequestData"), true); }
            case "Get15118EVCertificate" -> {
                fields(n, "iso15118SchemaVersion", "action", "exiRequest");
                text(n, "iso15118SchemaVersion", 50);
                oneOf(text(n, "action", 10), Set.of("Install", "Update"));
                Base64.getDecoder().decode(text(n, "exiRequest", 5600));
            }
            case "Authorize" -> {
                fields(n, "certificate", "idToken", "iso15118CertificateHashData");
                fields(n.get("idToken"), "idToken"); text(n.get("idToken"), "idToken", 20);
                if (n.has("certificate")) { text(n, "certificate", 5500); }
                if (n.has("iso15118CertificateHashData")) {
                    var hashes = n.get("iso15118CertificateHashData");
                    require(hashes.isArray() && hashes.size() <= 4);
                    for (var h : hashes) { hash(h, true); }
                }
            }
            default -> throw new IllegalArgumentException("Unsupported PnC message");
        }
        return n;
    }

    public static String responseStatus(String message, String data) {
        var n = parse(data);
        var status = text(n, "status", 32);
        Set<String> statuses = switch (message) {
            case "DeleteCertificate" -> Set.of("Accepted", "Failed", "NotFound");
            case "InstallCertificate" -> Set.of("Accepted", "Rejected", "Failed");
            case "GetInstalledCertificateIds" -> Set.of("Accepted", "NotFound");
            case "TriggerMessage" -> Set.of("Accepted", "Rejected", "NotImplemented");
            case "CertificateSigned" -> Set.of("Accepted", "Rejected");
            default -> throw new IllegalArgumentException("Unsupported response");
        };
        oneOf(status, statuses);
        if (message.equals("GetInstalledCertificateIds")) {
            fields(n, "status", "certificateHashDataChain");
            if (n.has("certificateHashDataChain")) {
                var chains = n.get("certificateHashDataChain");
                require(chains.isArray() && chains.size() <= 64);
                for (var c : chains) {
                    fields(c, "certificateType", "certificateHashData", "childCertificateHashData");
                    oneOf(text(c, "certificateType", 50), CERT_TYPES);
                    hash(c.get("certificateHashData"), false);
                    if (c.has("childCertificateHashData")) {
                        var children = c.get("childCertificateHashData");
                        require(children.isArray() && children.size() <= 4);
                        for (var h : children) { hash(h, false); }
                    }
                }
            }
        } else { fields(n, "status"); }
        return status;
    }

    public static String text(JsonNode n, String key, int max) {
        require(n != null && n.isObject());
        var v = n.get(key);
        require(v != null && v.isString() && !v.asString().isEmpty() && v.asString().length() <= max);
        return v.asString();
    }

    private static void hash(JsonNode n, boolean ocsp) {
        if (ocsp) { fields(n, "hashAlgorithm", "issuerNameHash", "issuerKeyHash", "serialNumber", "responderURL"); }
        else { fields(n, "hashAlgorithm", "issuerNameHash", "issuerKeyHash", "serialNumber"); }
        var algorithm = text(n, "hashAlgorithm", 10);
        oneOf(algorithm, Set.of("SHA256", "SHA384", "SHA512"));
        int length = switch (algorithm) { case "SHA256" -> 64; case "SHA384" -> 96; default -> 128; };
        for (String k : Set.of("issuerNameHash", "issuerKeyHash")) {
            var h = text(n, k, 128); require(h.length() == length && h.matches("[0-9a-fA-F]+"));
        }
        require(text(n, "serialNumber", 40).matches("[0-9a-fA-F]+"));
        if (ocsp) { text(n, "responderURL", 512); }
    }

    private static void fields(JsonNode n, String... names) {
        require(n != null && n.isObject());
        var allowed = Set.of(names);
        for (var key : n.propertyNames()) { require(allowed.contains(key)); }
    }

    private static void oneOf(String value, Set<String> allowed) { require(allowed.contains(value)); }
    private static void require(boolean valid) {
        if (!valid) { throw new IllegalArgumentException("Invalid PnC payload"); }
    }
}
