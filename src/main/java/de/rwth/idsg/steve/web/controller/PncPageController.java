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
package de.rwth.idsg.steve.web.controller;

import de.rwth.idsg.steve.service.pnc.PncService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class PncPageController {
    private final PncService service;
    private final de.rwth.idsg.steve.service.ChargePointService stations;
    public PncPageController(PncService service, de.rwth.idsg.steve.service.ChargePointService stations) {
        this.service = service;
        this.stations = stations;
    }
    @GetMapping("/manager/pnc")
    public String page(Model model) {
        model.addAttribute("pncEnabled", service.enabled());
        var connected = stations.getChargeBoxIdsOfConnectedJsonStations();
        model.addAttribute("pncStations", stations.getChargePoints(de.rwth.idsg.steve.ocpp.OcppVersion.V_16).stream()
            .filter(cp -> cp.getOcppProtocol() == de.rwth.idsg.steve.ocpp.OcppProtocol.V_16_JSON)
            .sorted(java.util.Comparator.comparing(de.rwth.idsg.steve.repository.dto.ChargePointSelect::getChargeBoxId))
            .map(cp -> java.util.Map.of("id", cp.getChargeBoxId(), "connected", connected.contains(cp.getChargeBoxId()))).toList());
        return "pnc";
    }
}
