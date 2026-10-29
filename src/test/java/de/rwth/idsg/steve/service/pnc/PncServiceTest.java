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

import de.rwth.idsg.steve.ocpp.OcppCallback;
import de.rwth.idsg.steve.service.ChargePointServiceClient;
import ocpp.cs._2015._10.DataTransferRequest;
import ocpp.cs._2015._10.DataTransferStatus;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class PncServiceTest {
    private final PncV2gSigner signer = mock(PncV2gSigner.class);
    private final ChargePointServiceClient client = mock(ChargePointServiceClient.class);
    private final PncContractService contracts = mock(PncContractService.class);
    private final PncService service = new PncService(true, signer, client, contracts, new PncCertificateInventory());
    @AfterEach void close() { service.close(); }

    private DataTransferRequest request(String message, String data) {
        return new DataTransferRequest().withVendorId(PncProtocol.VENDOR).withMessageId(message).withData(data);
    }

    @Test
    void failsClosedWithoutProvidersAndRejectsMalformedWireData() {
        when(contracts.authorize(any(), any())).thenReturn("{\"idTokenInfo\":{\"status\":\"Invalid\"},\"certificateStatus\":\"NoCertificateAvailable\"}");
        var auth = service.handle(request("Authorize", "{\"idToken\":{\"idToken\":\"DEABC123\"}}"), "station");
        assertEquals(DataTransferStatus.ACCEPTED, auth.getStatus());
        assertTrue(auth.getData().contains("Invalid"));
        assertEquals(DataTransferStatus.REJECTED, service.handle(request("SignCertificate", "[]"), "station").getStatus());
        assertEquals(DataTransferStatus.UNKNOWN_MESSAGE_ID, service.handle(request("CertificateSigned", "{}"), "station").getStatus());
        verifyNoInteractions(client);
    }

    @Test
    void deduplicatesCsrAndRejectsConcurrentRotationForSameStation() throws Exception {
        var csr = mock(PKCS10CertificationRequest.class);
        when(csr.getEncoded()).thenReturn(new byte[]{1, 2, 3});
        when(signer.validate(any())).thenReturn(csr);
        var request = request("SignCertificate", "{\"csr\":\"fixture\"}");
        assertTrue(service.handle(request, "station").getData().contains("Accepted"));
        assertTrue(service.handle(request, "station").getData().contains("Accepted"));
        assertEquals(1, service.jobs().size());
        when(csr.getEncoded()).thenReturn(new byte[]{4, 5, 6});
        assertTrue(service.handle(request, "station").getData().contains("Rejected"));
        assertEquals(1, service.jobs().size());
    }

    @Test
    void queueHasHardCapacity() {
        for (int i = 0; i < 16; i++) { service.command("station" + i, "TriggerMessage", "{}"); }
        assertThrows(IllegalStateException.class, () -> service.command("overflow", "TriggerMessage", "{}"));
        assertEquals(16, service.jobs().size());
    }

    @SuppressWarnings("unchecked")
    @Test
    void outerAcceptedDoesNotMeanInnerAcceptedAndHistoryIsBounded() {
        doAnswer(invocation -> {
            OcppCallback<ocpp.cp._2015._10.DataTransferResponse> callback = invocation.getArgument(1);
            callback.success(null, "station", new ocpp.cp._2015._10.DataTransferResponse()
                .withStatus(ocpp.cp._2015._10.DataTransferStatus.ACCEPTED).withData("{\"status\":\"Rejected\"}"));
            return null;
        }).when(client).pncDataTransfer(any(), any(OcppCallback.class));
        var job = service.command("station", "TriggerMessage", "{}");
        assertEquals("Rejected", job.state());
        assertEquals("Accepted", job.outerStatus());
        assertEquals("Rejected", job.innerStatus());
        for (int i = 0; i < 300; i++) { service.command("station", "TriggerMessage", "{}"); }
        assertEquals(256, service.jobs().size());
    }
}
