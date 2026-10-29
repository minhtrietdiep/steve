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
package de.rwth.idsg.steve.web.api;

import de.rwth.idsg.steve.service.pnc.PncService;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

/** Admin-session/CSRF or existing API-key protected entry points. */
@RestController
@RequestMapping({"/manager/pnc", "/api/v1/pnc"})
public class PncController {
    public record Command(String station, String message, String data) { }
    private final PncService service;
    public PncController(PncService service) { this.service = service; }

    @GetMapping("/jobs")
    public List<PncService.Job> jobs() { return service.jobs(); }

    @GetMapping("/lab-roots")
    public List<PncService.LabRoot> roots() throws Exception { return service.labRoots(); }

    @GetMapping("/certificates")
    public de.rwth.idsg.steve.service.pnc.PncCertificateInventory.View certificates(@RequestParam String station) {
        if (station.isBlank() || station.length() > 255) { throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid station"); }
        return service.certificates(station);
    }

    @PostMapping("/commands")
    public PncService.Job command(@RequestBody Command command) {
        try { return service.command(command.station(), command.message(), command.data()); }
        catch (IllegalArgumentException e) { throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid PnC command"); }
        catch (IllegalStateException e) { throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "PnC unavailable or busy"); }
    }
}
