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

import de.rwth.idsg.steve.ocpp.CommunicationTask;
import de.rwth.idsg.steve.ocpp.OcppCallback;
import de.rwth.idsg.steve.ocpp.OcppProtocol;
import de.rwth.idsg.steve.ocpp.ws.data.OcppJsonError;
import de.rwth.idsg.steve.repository.dto.ChargePointSelect;
import de.rwth.idsg.steve.service.ChargePointServiceClient;
import de.rwth.idsg.steve.web.dto.ocpp.DataTransferParams;
import jakarta.annotation.PreDestroy;
import ocpp.cs._2015._10.DataTransferRequest;
import ocpp.cs._2015._10.DataTransferResponse;
import ocpp.cs._2015._10.DataTransferStatus;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.ScheduledFuture;

/** Bounded asynchronous PnC jobs. The station's acknowledgement completes a job. */
@Service
public class PncService {
    public record Job(String id, String station, String message, String state, String outerStatus,
                      String innerStatus, Instant created, String fingerprint) { }

    private final boolean enabled;
    private final PncV2gSigner signer;
    private final ChargePointServiceClient client;
    private final PncContractService contracts;
    private final PncCertificateInventory inventory;
    private final ScheduledThreadPoolExecutor worker;
    private final Map<String, Job> jobs = new LinkedHashMap<>();
    private final Map<String, ScheduledFuture<?>> deadlines = new LinkedHashMap<>();
    private static final int MAX_PENDING = 16;
    private static final int MAX_HISTORY = 256;

    public PncService(@Value("${steve.pnc.enabled:false}") boolean enabled, PncV2gSigner signer,
                      ChargePointServiceClient client, PncContractService contracts, PncCertificateInventory inventory) {
        this.enabled = enabled;
        this.signer = signer;
        this.client = client;
        this.contracts = contracts;
        this.inventory = inventory;
        worker = new ScheduledThreadPoolExecutor(2, r -> {
            Thread t = new Thread(r, "pnc-lab-worker"); t.setDaemon(true); return t;
        });
        worker.setRemoveOnCancelPolicy(true);
    }

    public boolean enabled() { return enabled; }

    public record LabRoot(String certificateType, String certificate) { }
    public List<LabRoot> labRoots() throws Exception {
        var roots = new ArrayList<LabRoot>();
        if (signer.available()) { roots.add(new LabRoot("V2GRootCertificate", signer.publicRoot())); }
        if (contracts.available()) { roots.add(new LabRoot("MORootCertificate", contracts.publicRoot())); }
        return roots;
    }

    public PncCertificateInventory.View certificates(String station) { return inventory.get(station); }

    public DataTransferResponse handle(DataTransferRequest request, String station) {
        if (!enabled) { return outer(DataTransferStatus.REJECTED); }
        if (!PncProtocol.INBOUND.contains(request.getMessageId() == null ? "" : request.getMessageId())) {
            return outer(DataTransferStatus.UNKNOWN_MESSAGE_ID);
        }
        try {
            var payload = PncProtocol.request(request.getMessageId(), request.getData(), true);
            return switch (request.getMessageId()) {
                case "SignCertificate" -> signingResponse(station, PncProtocol.text(payload, "csr", 5500));
                case "Authorize" -> new DataTransferResponse().withStatus(DataTransferStatus.ACCEPTED)
                    .withData(contracts.authorize(payload, station));
                case "GetCertificateStatus" -> new DataTransferResponse().withStatus(DataTransferStatus.ACCEPTED)
                    .withData(contracts.certificateStatus(payload));
                // EV provisioning has no configured provider. Never fabricate an EXI response.
                default -> inner("Failed");
            };
        } catch (Exception ignored) {
            // Payloads, CSRs and exception text may contain sensitive input. Do not log them.
            return outer(DataTransferStatus.REJECTED);
        }
    }

    private DataTransferResponse signingResponse(String station, String pem) {
        try { return inner(acceptCsr(station, pem)); }
        catch (Exception ignored) { return inner("Rejected"); }
    }

    private String acceptCsr(String station, String pem) throws Exception {
        var csr = signer.validate(pem);
        var fingerprint = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(csr.getEncoded()));
        final Job job;
        synchronized (this) {
            for (var existing : jobs.values()) {
                if (existing.station().equals(station) && fingerprint.equals(existing.fingerprint())) {
                    return pending(existing) || existing.state().equals("Succeeded") ? "Accepted" : "Rejected";
                }
                if (existing.station().equals(station) && existing.message().equals("CertificateSigned") && pending(existing)) {
                    return "Rejected";
                }
            }
            job = addJob(station, "CertificateSigned", fingerprint);
        }
        try {
            // Same decoupling delay used by SteVe's native signer: response precedes delivery.
            worker.schedule(() -> {
                try {
                    if (!isPending(job.id())) { return; }
                    var chain = signer.sign(csr);
                    send(job, PncProtocol.JSON.writeValueAsString(new PncProtocol.CertificateSigned(chain)));
                } catch (Exception ignored) { finish(job.id(), "Failed", null, null); }
            }, 5, TimeUnit.SECONDS);
        } catch (RuntimeException e) { finish(job.id(), "Failed", null, null); return "Rejected"; }
        return "Accepted";
    }

    public Job command(String station, String message, String data) {
        if (!enabled) { throw new IllegalStateException("PnC is disabled"); }
        PncProtocol.request(message, data, false);
        if (message.equals("CertificateSigned")) {
            throw new IllegalArgumentException("CertificateSigned is delivered by the signing workflow");
        }
        var job = addJob(station, message, null);
        try { send(job, data); }
        catch (RuntimeException e) { finish(job.id(), "Failed", null, null); }
        return get(job.id());
    }

    private synchronized Job addJob(String station, String message, String fingerprint) {
        if (station == null || station.isBlank() || station.length() > 255) { throw new IllegalArgumentException("Invalid station"); }
        if (jobs.values().stream().filter(PncService::pending).count() >= MAX_PENDING) {
            throw new IllegalStateException("PnC queue is full");
        }
        while (jobs.size() >= MAX_HISTORY) {
            var removable = jobs.values().stream().filter(j -> !pending(j)).findFirst().orElseThrow();
            jobs.remove(removable.id());
        }
        var job = new Job(UUID.randomUUID().toString(), station, message, "Pending", null, null, Instant.now(), fingerprint);
        jobs.put(job.id(), job);
        deadlines.put(job.id(), worker.schedule(() -> finish(job.id(), "TimedOut", null, null), 45, TimeUnit.SECONDS));
        return job;
    }

    private void send(Job job, String data) {
        if (!isPending(job.id())) { return; }
        PncProtocol.request(job.message(), data, false);
        var params = new DataTransferParams();
        params.setChargePointSelectList(List.of(new ChargePointSelect(OcppProtocol.V_16_JSON, job.station())));
        params.setVendorId(PncProtocol.VENDOR);
        params.setMessageId(job.message());
        params.setData(data);
        client.pncDataTransfer(params, new OcppCallback<>() {
            @Override
            public void success(CommunicationTask<?, ocpp.cp._2015._10.DataTransferResponse> task, String station,
                                ocpp.cp._2015._10.DataTransferResponse response) {
                var outer = response.getStatus() == null ? "Missing" : response.getStatus().value();
                if (!outer.equals("Accepted")) { finish(job.id(), "Rejected", outer, null); return; }
                try {
                    var inner = PncProtocol.responseStatus(job.message(), response.getData());
                    var state = inner.equals("Accepted") ? "Succeeded" : inner.equals("NotFound") ? "NotFound" : "Rejected";
                    synchronized (PncService.this) {
                        if (!isPending(job.id())) { return; }
                        if (job.message().equals("GetInstalledCertificateIds")) {
                            inventory.update(job.station(), PncProtocol.parse(data), PncProtocol.parse(response.getData()), job.created());
                        } else if (inner.equals("Accepted")) {
                            if (job.message().equals("DeleteCertificate")) {
                                inventory.remove(job.station(), PncProtocol.parse(data).get("certificateHashData"));
                            } else if (job.message().equals("InstallCertificate")) {
                                inventory.invalidate(job.station(), PncProtocol.parse(data).get("certificateType").asString());
                            } else if (job.message().equals("CertificateSigned")) { inventory.invalidate(job.station(), "V2GCertificateChain"); }
                        }
                        finish(job.id(), state, outer, inner);
                    }
                } catch (Exception ignored) { finish(job.id(), "InvalidResponse", outer, null); }
            }

            @Override
            public void success(CommunicationTask<?, ocpp.cp._2015._10.DataTransferResponse> task, String station, OcppJsonError error) {
                finish(job.id(), "CallError", null, null);
            }

            @Override
            public void failed(CommunicationTask<?, ocpp.cp._2015._10.DataTransferResponse> task, String station, Exception e) {
                finish(job.id(), "Failed", null, null);
            }
        });
    }

    private synchronized boolean isPending(String id) { return jobs.containsKey(id) && pending(jobs.get(id)); }

    private synchronized void finish(String id, String state, String outer, String inner) {
        var job = jobs.get(id);
        if (job == null || !pending(job)) { return; }
        var deadline = deadlines.remove(id);
        if (deadline != null) { deadline.cancel(false); }
        jobs.put(id, new Job(id, job.station(), job.message(), state, outer, inner, job.created(), job.fingerprint()));
    }

    public synchronized List<Job> jobs() { return new ArrayList<>(jobs.values()); }
    public synchronized Job get(String id) { return jobs.get(id); }
    private static boolean pending(Job j) { return j.state().equals("Pending"); }
    private static DataTransferResponse outer(DataTransferStatus status) { return new DataTransferResponse().withStatus(status); }
    private static DataTransferResponse inner(String status) {
        return outer(DataTransferStatus.ACCEPTED).withData(PncProtocol.JSON.writeValueAsString(new PncProtocol.Status(status)));
    }

    @PreDestroy
    public void close() { worker.shutdownNow(); }

}
