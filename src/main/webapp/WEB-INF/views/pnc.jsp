<%--

    SteVe - SteckdosenVerwaltung - https://github.com/steve-community/steve
    Copyright (C) 2013-2026 SteVe Community Team
    All Rights Reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

--%>
<%@ include file="00-header.jsp" %>
<link rel="stylesheet" href="${ctxPath}/static/css/pnc.css">
<div class="content pnc-page">
    <h2>Plug &amp; Charge lab</h2>
    <div class="left-menu" aria-label="Plug and Charge operations">
        <ul>
            <li><a href="#InstallCertificate" data-pnc-operation="InstallCertificate">Install Certificate</a></li>
            <li><a href="#GetInstalledCertificateIds" data-pnc-operation="GetInstalledCertificateIds">Get Installed Certificate IDs</a></li>
            <li><a href="#DeleteCertificate" data-pnc-operation="DeleteCertificate">Delete Certificate</a></li>
            <li><a href="#TriggerMessage" data-pnc-operation="TriggerMessage">Request V2G Certificate</a></li>
        </ul>
    </div>
    <div class="op16-content pnc-panel">
        <form id="pnc-command">
            <input type="hidden" id="pnc-message" value="InstallCertificate">
            <section><span>Charge Point with OCPP 1.6J</span></section>
            <table class="userInput">
                <tr><td><label for="pnc-station">Charge Point:</label></td><td>
                    <select id="pnc-station" required>
                        <option value="">Select a charge point</option>
                        <c:forEach items="${pncStations}" var="station">
                            <option value="<c:out value='${station.id}'/>"><c:out value="${station.id}"/> (${station.connected ? 'connected' : 'offline'})</option>
                        </c:forEach>
                    </select>
                    <p class="pnc-help">Only this development backend's OCPP 1.6J charge points are listed.
                        <a href="${ctxPath}/manager/chargepoints">Manage charge points</a></p>
                </td></tr>
            </table>
            <section><span id="pnc-operation-title">Install Certificate</span></section>
            <div id="pnc-install">
                <p class="info">Install a root certificate in the charge point's ISO 15118 trust store.</p>
                <table class="userInput">
                    <tr><td><label for="pnc-certificate-type">Certificate Type:</label></td><td>
                        <select id="pnc-certificate-type">
                            <option value="V2GRootCertificate">V2G Root Certificate</option>
                            <option value="MORootCertificate">MO Root Certificate</option>
                        </select>
                        <p id="pnc-root-purpose" class="pnc-help">Trust root for V2G / SECC certificate chains.</p>
                    </td></tr>
                    <tr><td><label for="pnc-certificate">Certificate (PEM encoded, X.509):</label></td><td>
                        <textarea id="pnc-certificate" rows="10" maxlength="5500" spellcheck="false" placeholder="-----BEGIN CERTIFICATE-----&#10;Paste the certificate here&#10;-----END CERTIFICATE-----"></textarea>
                        <p class="pnc-help">Paste the complete PEM text with normal line breaks.</p>
                        <label class="pnc-file-label" for="pnc-certificate-file">Or read a PEM file:</label>
                        <input id="pnc-certificate-file" type="file" accept=".pem,.crt,.cer,.txt">
                        <p><button type="button" id="pnc-use-lab-root">Use lab root</button> <span id="pnc-file-status" class="pnc-help" role="status"></span></p>
                    </td></tr>
                </table>
            </div>
            <div id="pnc-query" hidden>
                <p class="info">Read the certificates installed on the selected charge point. The reported IDs become available for deletion below.</p>
                <table class="userInput"><tr><td><label for="pnc-query-type">Certificate Type:</label></td><td>
                    <select id="pnc-query-type"><option value="">All ISO 15118 certificate types</option>
                        <option value="V2GRootCertificate">V2G Root Certificate</option><option value="MORootCertificate">MO Root Certificate</option>
                        <option value="V2GCertificateChain">V2G Certificate Chain</option></select>
                </td></tr></table>
            </div>
            <div id="pnc-delete" hidden>
                <p class="info">First read the installed certificate IDs from this charge point, then choose the certificate to delete.</p>
                <table class="userInput"><tr><td><label for="pnc-installed-id">Installed Certificate:</label></td><td>
                    <select id="pnc-installed-id" disabled><option value="">Read installed certificate IDs first</option></select>
                    <p><button type="button" id="pnc-read-certificates">Read certificate IDs</button></p>
                </td></tr></table>
            </div>
            <div id="pnc-trigger" hidden>
                <p class="info">Ask the charge point to generate a key pair and request its own V2G / SECC certificate.
                    The lab signs the CSR and returns the certificate automatically.</p>
                <p class="pnc-help">The charge point must support the wrapped ISO 15118 signing flow. No certificate text is needed here.</p>
            </div>
            <table class="userInput"><tr><td></td><td><div class="submit-button">
                <input type="submit" id="pnc-submit" value="Install Certificate">
            </div></td></tr></table>
            <p id="pnc-disabled" class="warning" ${pncEnabled ? 'hidden' : ''}>Plug &amp; Charge is disabled on this backend.</p>
            <p id="pnc-result" role="status" aria-live="polite" hidden></p>
            <details class="pnc-advanced"><summary>Advanced: JSON payload</summary>
                <p class="pnc-help">Generated from the form. The DataTransfer wrapper is added automatically.</p>
                <textarea id="pnc-data" rows="6" readonly aria-label="Generated JSON payload"></textarea>
            </details>
        </form>
        <section><span>Installed ISO 15118 Certificates</span></section>
        <p id="pnc-inventory-status" class="pnc-help">Select a charge point to see its reported certificates.</p>
        <div class="pnc-table-scroll"><table class="res" id="pnc-inventory-table" hidden>
            <thead><tr><th>Certificate Type</th><th>Serial Number</th><th>Hash Algorithm</th></tr></thead>
            <tbody id="pnc-inventory"></tbody>
        </table></div>
        <section><span>Recent Jobs</span></section>
        <p><button type="button" id="pnc-refresh">Refresh results</button></p>
        <div class="pnc-table-scroll"><table class="res">
            <thead><tr><th>Created</th><th>Charge Point</th><th>Operation</th><th>Result</th><th>Transfer Status</th><th>Operation Status</th></tr></thead>
            <tbody id="pnc-jobs"><tr><td colspan="6">No recent jobs.</td></tr></tbody>
        </table></div>
        <p class="pnc-help">Results confirm the charge point's acknowledgement. Recent history and certificate IDs reset when the app restarts.</p>
        <details class="pnc-advanced"><summary>Configuration and lab support</summary>
            <p><a href="${ctxPath}/manager/operations/v1.6/GetConfiguration">Get Configuration</a> and
                <a href="${ctxPath}/manager/operations/v1.6/ChangeConfiguration">Change Configuration</a> support ISO15118PnCEnabled.</p>
            <p>OCA v1.0 over OCPP 1.6J. Lab contract validation and OCSP use configured test contracts.
                EV certificate provisioning is unavailable.</p>
        </details>
    </div>
</div>
<script src="${ctxPath}/static/js/pnc.js"></script>
<script>
(() => {
    const csrfHeader = '${_csrf.headerName}', csrfToken = '${_csrf.token}';
    window.PncUI.mount({base: '${ctxPath}/manager/pnc', csrfHeader, csrfToken, enabled: ${pncEnabled}});
})();
</script>
<%@ include file="00-footer.jsp" %>
