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

import org.springframework.stereotype.Service;
import tools.jackson.databind.JsonNode;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** PnC-only, bounded certificate hashes reported by stations; never native OCPP trust. */
@Service
public class PncCertificateInventory {
    public record Entry(String id, String station, String certificateType, Map<String, String> certificateHashData) { }
    public record View(String station, Instant queriedAt, List<Entry> certificates) { }
    private final Map<String, View> stations = new LinkedHashMap<>();

    public synchronized View get(String station) {
        return stations.getOrDefault(station, new View(station, null, List.of()));
    }

    public synchronized void update(String station, JsonNode request, JsonNode response, Instant requestedAt) {
        var previous = get(station);
        if (previous.queriedAt() != null && previous.queriedAt().isAfter(requestedAt)) { return; }
        Set<String> types = new java.util.HashSet<>();
        if (request.has("certificateType")) {
            request.get("certificateType").forEach(t -> types.add(t.asString()));
        }
        if (types.isEmpty()) { types.addAll(PncProtocol.CERT_TYPES); }
        var entries = new LinkedHashMap<String, Entry>();
        previous.certificates().stream().filter(e -> !types.contains(e.certificateType())).forEach(e -> entries.put(e.id(), e));
        if (response.get("status").asString().equals("Accepted") && response.has("certificateHashDataChain")) {
            for (var chain : response.get("certificateHashDataChain")) {
                var type = chain.get("certificateType").asString();
                if (!types.contains(type)) { continue; }
                add(entries, station, type, chain.get("certificateHashData"));
                if (chain.has("childCertificateHashData")) {
                    for (var child : chain.get("childCertificateHashData")) { add(entries, station, type, child); }
                }
            }
        }
        if (entries.size() > 320) { throw new IllegalArgumentException("PnC inventory limit exceeded"); }
        put(new View(station, requestedAt, List.copyOf(entries.values())));
    }

    public synchronized void remove(String station, JsonNode hash) {
        var previous = get(station);
        var remaining = previous.certificates().stream().filter(e -> !identity(e.certificateHashData()).equals(identity(hashMap(hash)))).toList();
        put(new View(station, Instant.now(), remaining));
    }

    public synchronized void invalidate(String station, String type) {
        var previous = get(station);
        put(new View(station, Instant.now(), previous.certificates().stream().filter(e -> !e.certificateType().equals(type)).toList()));
    }

    private void put(View view) {
        stations.remove(view.station());
        if (stations.size() >= 32) { stations.remove(stations.keySet().iterator().next()); }
        stations.put(view.station(), view);
    }

    private static void add(Map<String, Entry> entries, String station, String type, JsonNode hash) {
        var fields = hashMap(hash);
        try {
            var id = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest((type + identity(fields)).getBytes(StandardCharsets.UTF_8)));
            entries.put(id, new Entry(id, station, type, fields));
        } catch (java.security.NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }

    private static Map<String, String> hashMap(JsonNode hash) {
        return Map.of("hashAlgorithm", hash.get("hashAlgorithm").asString(), "issuerNameHash", hash.get("issuerNameHash").asString(),
            "issuerKeyHash", hash.get("issuerKeyHash").asString(), "serialNumber", hash.get("serialNumber").asString());
    }

    private static String identity(Map<String, String> fields) {
        return (fields.get("hashAlgorithm") + ":" + fields.get("issuerNameHash") + ":" + fields.get("issuerKeyHash")
            + ":" + new BigInteger(fields.get("serialNumber"), 16).toString(16)).toLowerCase(Locale.ROOT);
    }
}
