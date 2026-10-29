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
import java.time.Instant;
import static org.junit.jupiter.api.Assertions.*;

class PncCertificateInventoryTest {
    private static String response(String type, String serial) {
        return "{\"status\":\"Accepted\",\"certificateHashDataChain\":[{\"certificateType\":\"" + type
            + "\",\"certificateHashData\":{\"hashAlgorithm\":\"SHA256\",\"issuerNameHash\":\"" + "ab".repeat(32)
            + "\",\"issuerKeyHash\":\"" + "cd".repeat(32) + "\",\"serialNumber\":\"" + serial + "\"}}]}";
    }

    @Test
    void keepsStationsSeparateAndDoesNotResurrectAnOlderSnapshot() {
        var inventory = new PncCertificateInventory();
        var now = Instant.now();
        inventory.update("station-a", PncProtocol.parse("{}"), PncProtocol.parse(response("V2GRootCertificate", "01")), now);
        inventory.update("station-b", PncProtocol.parse("{}"), PncProtocol.parse(response("MORootCertificate", "02")), now);
        assertEquals("01", inventory.get("station-a").certificates().getFirst().certificateHashData().get("serialNumber"));
        inventory.update("station-a", PncProtocol.parse("{}"), PncProtocol.parse("{\"status\":\"NotFound\"}"), now.plusSeconds(2));
        inventory.update("station-a", PncProtocol.parse("{}"), PncProtocol.parse(response("V2GRootCertificate", "01")), now);
        assertTrue(inventory.get("station-a").certificates().isEmpty());
        assertEquals(1, inventory.get("station-b").certificates().size());
    }

    @Test
    void partialReadsAndDeletionRetainOtherCertificateTypes() {
        var inventory = new PncCertificateInventory();
        var now = Instant.now();
        inventory.update("station", PncProtocol.parse("{}"), PncProtocol.parse(response("V2GRootCertificate", "01")), now);
        inventory.update("station", PncProtocol.parse("{\"certificateType\":[\"MORootCertificate\"]}"),
            PncProtocol.parse(response("MORootCertificate", "02")), now.plusSeconds(1));
        assertEquals(2, inventory.get("station").certificates().size());
        var root = inventory.get("station").certificates().getFirst();
        inventory.remove("station", PncProtocol.JSON.valueToTree(root.certificateHashData()));
        assertEquals("MORootCertificate", inventory.get("station").certificates().getFirst().certificateType());
        inventory.invalidate("station", "MORootCertificate");
        assertTrue(inventory.get("station").certificates().isEmpty());
    }

    @Test
    void boundsRememberedStationsAndFlattensChainChildren() {
        var inventory = new PncCertificateInventory();
        for (int i = 0; i < 33; i++) { inventory.update("station" + i, PncProtocol.parse("{}"),
            PncProtocol.parse(response("V2GRootCertificate", "01")), Instant.now()); }
        assertNull(inventory.get("station0").queriedAt());
        assertEquals(1, inventory.get("station32").certificates().size());
        var data = PncProtocol.parse(response("V2GCertificateChain", "01"));
        var chain = (tools.jackson.databind.node.ObjectNode) data.get("certificateHashDataChain").get(0);
        var child = chain.get("certificateHashData").deepCopy();
        ((tools.jackson.databind.node.ObjectNode) child).put("serialNumber", "02");
        chain.putArray("childCertificateHashData").add(child);
        inventory.update("chain", PncProtocol.parse("{}"), data, Instant.now());
        assertEquals(2, inventory.get("chain").certificates().size());
    }
}
