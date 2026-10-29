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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

class PncProtocolTest {
    @Test
    void websocketMapperPreservesOpaqueJsonStringsInBothDirections() {
        var mapper = de.rwth.idsg.steve.ocpp.ws.JsonObjectMapper.INSTANCE.getMapper();
        var data = "{\"csr\":\"quotes & <tag> ' \\n and UTF-8: é\"}";
        var wire = PncProtocol.JSON.writeValueAsString(java.util.Map.of("vendorId", PncProtocol.VENDOR,
            "messageId", "SignCertificate", "data", data));
        var inbound = mapper.readValue(wire, ocpp.cs._2015._10.DataTransferRequest.class);
        assertEquals(data, inbound.getData());
        var outbound = new ocpp.cp._2015._10.DataTransferRequest().withVendorId(PncProtocol.VENDOR)
            .withMessageId("CertificateSigned").withData(data);
        assertEquals(data, PncProtocol.parse(mapper.writeValueAsString(outbound)).get("data").asString());
        var responseWire = PncProtocol.JSON.writeValueAsString(java.util.Map.of("status", "Accepted", "data", data));
        assertEquals(data, mapper.readValue(responseWire, ocpp.cp._2015._10.DataTransferResponse.class).getData());
        assertEquals(data, PncProtocol.parse(mapper.writeValueAsString(new ocpp.cs._2015._10.DataTransferResponse()
            .withStatus(ocpp.cs._2015._10.DataTransferStatus.ACCEPTED).withData(data))).get("data").asString());
    }

    @ParameterizedTest
    @ValueSource(strings = {"null", "[]", "1", "\"string\"", "{} {}", "{\"csr\":null}",
        "{\"csr\":\"x\",\"csr\":\"y\"}", "{\"csr\":\"x\",\"certificateType\":\"V2GCertificate\"}",
        "{\"csr\":\"\"}", "{\"csr\":10}"})
    void rejectsInvalidSigningPayload(String data) {
        assertThrows(Exception.class, () -> PncProtocol.request("SignCertificate", data, true));
    }

    @Test
    void enforcesDirectionsAndBounds() {
        assertThrows(Exception.class, () -> PncProtocol.request("TriggerMessage", "{}", true));
        assertThrows(Exception.class, () -> PncProtocol.request("SignCertificate", "{\"csr\":\"x\"}", false));
        assertThrows(Exception.class, () -> PncProtocol.request("SignCertificate", "{\"csr\":\"" + "x".repeat(5501) + "\"}", true));
        assertThrows(Exception.class, () -> PncProtocol.parse(" ".repeat(32769)));
        assertThrows(Exception.class, () -> PncProtocol.parse("[".repeat(13) + "0" + "]".repeat(13)));
        assertEquals("x", PncProtocol.request("SignCertificate", "{\"csr\":\"x\"}", true).get("csr").asString());
    }

    @Test
    void usesAdaptedV10Fields() {
        PncProtocol.request("TriggerMessage", "{}", false);
        assertThrows(Exception.class, () -> PncProtocol.request("TriggerMessage", "{\"requestedMessage\":\"SignV2GCertificate\"}", false));
        PncProtocol.request("Authorize", "{\"idToken\":{\"idToken\":\"DEABC123456789\"}}", true);
        assertThrows(Exception.class, () -> PncProtocol.request("Authorize", "{\"idToken\":{\"idToken\":\"abc\",\"type\":\"eMAID\"}}", true));
        PncProtocol.request("GetInstalledCertificateIds", "{\"certificateType\":[\"V2GCertificateChain\"]}", false);
        assertThrows(Exception.class, () -> PncProtocol.request("InstallCertificate", "{\"certificateType\":\"CentralSystemRootCertificate\",\"certificate\":\"x\"}", false));
        assertThrows(Exception.class, () -> PncProtocol.request("Get15118EVCertificate", "{\"iso15118SchemaVersion\":\"v\",\"action\":\"Install\",\"exiRequest\":\"not base64!\"}", true));
    }

    @Test
    void validatesInnerResponsesIndependently() {
        assertEquals("Rejected", PncProtocol.responseStatus("CertificateSigned", "{\"status\":\"Rejected\"}"));
        assertEquals("NotFound", PncProtocol.responseStatus("DeleteCertificate", "{\"status\":\"NotFound\"}"));
        assertThrows(Exception.class, () -> PncProtocol.responseStatus("CertificateSigned", "{\"status\":\"Failed\"}"));
        assertThrows(Exception.class, () -> PncProtocol.responseStatus("GetInstalledCertificateIds", "{\"status\":\"Accepted\",\"certificateHashDataChain\":[{}]}"));
    }
}
