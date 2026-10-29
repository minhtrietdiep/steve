(function (root) {
    'use strict';
    const labels = {InstallCertificate:'Install Certificate', GetInstalledCertificateIds:'Get Installed Certificate IDs',
        DeleteCertificate:'Delete Certificate', TriggerMessage:'Request V2G Certificate'};
    const typeLabels = {V2GRootCertificate:'V2G Root Certificate', MORootCertificate:'MO Root Certificate', V2GCertificateChain:'V2G Certificate Chain'};
    const states = {Pending:'Waiting for charge point', Succeeded:'Succeeded', NotFound:'No matching certificates',
        Rejected:'Rejected', Failed:'Delivery failed', TimedOut:'Timed out', InvalidResponse:'Invalid response', CallError:'Protocol error'};

    function payload(message, fields, certificates) {
        if (message === 'InstallCertificate') {
            const certificate = fields.certificate.replace(/\r\n?/g, '\n').trim() + '\n';
            if (!certificate.startsWith('-----BEGIN CERTIFICATE-----\n') || !certificate.trimEnd().endsWith('-----END CERTIFICATE-----')
                || (certificate.match(/-----BEGIN CERTIFICATE-----/g) || []).length !== 1 || certificate.length > 5500) {
                throw new Error('Paste one complete PEM certificate, or choose a PEM certificate file.');
            }
            return {certificateType:fields.certificateType, certificate};
        }
        if (message === 'GetInstalledCertificateIds') { return fields.queryType ? {certificateType:[fields.queryType]} : {}; }
        if (message === 'DeleteCertificate') {
            const entry = certificates.find(c => c.id === fields.certificateId && c.station === fields.station);
            if (!entry) { throw new Error('Read this charge point\'s certificate IDs, then select the certificate to delete.'); }
            return {certificateHashData:entry.certificateHashData};
        }
        if (message === 'TriggerMessage') { return {}; }
        throw new Error('Choose an operation.');
    }

    function mount(config) {
        const $ = id => document.getElementById(id);
        let certificates = [], busy = false, budget = 0, timer = null, submittedJob = null;
        const fields = () => ({station:$('pnc-station').value, certificate:$('pnc-certificate').value,
            certificateType:$('pnc-certificate-type').value, queryType:$('pnc-query-type').value, certificateId:$('pnc-installed-id').value});
        function notice(message, error) {
            if (error) { submittedJob = null; }
            $('pnc-result').hidden = false;
            $('pnc-result').className = error ? 'pnc-result-error' : 'pnc-result-ok';
            $('pnc-result').textContent = message;
        }
        function clearNotice() { submittedJob = null; $('pnc-result').hidden = true; }
        function preview() {
            try { $('pnc-data').value = JSON.stringify(payload($('pnc-message').value, fields(), certificates), null, 2); }
            catch (e) { $('pnc-data').value = e.message; }
        }
        function operation(message) {
            if (!labels[message]) { message = 'InstallCertificate'; }
            $('pnc-message').value = message;
            $('pnc-operation-title').textContent = labels[message];
            $('pnc-submit').value = labels[message];
            $('pnc-install').hidden = message !== 'InstallCertificate';
            $('pnc-query').hidden = message !== 'GetInstalledCertificateIds';
            $('pnc-delete').hidden = message !== 'DeleteCertificate';
            $('pnc-trigger').hidden = message !== 'TriggerMessage';
            $('pnc-certificate').required = message === 'InstallCertificate';
            $('pnc-installed-id').required = message === 'DeleteCertificate';
            clearNotice();
            document.querySelectorAll('[data-pnc-operation]').forEach(a => {
                const active = a.dataset.pncOperation === message;
                a.classList.toggle('highlight', active);
                if (active) { a.setAttribute('aria-current', 'page'); } else { a.removeAttribute('aria-current'); }
            });
            preview();
        }
        function cell(row, value) {
            const td = document.createElement('td'); td.textContent = value || '—'; row.appendChild(td);
        }
        async function readInventory() {
            const station = $('pnc-station').value;
            if (!station) { renderInventory({station:'', queriedAt:null, certificates:[]}); return; }
            const response = await fetch(config.base + '/certificates?station=' + encodeURIComponent(station));
            if (!response.ok) { throw new Error('Could not load reported certificate IDs.'); }
            const view = await response.json();
            if ($('pnc-station').value === station && view.station === station) { renderInventory(view); }
        }
        function renderInventory(view) {
            certificates = view.certificates;
            const selected = $('pnc-installed-id').value;
            $('pnc-installed-id').replaceChildren(); $('pnc-inventory').replaceChildren();
            const placeholder = document.createElement('option'); placeholder.value = '';
            placeholder.textContent = certificates.length ? 'Select an installed certificate' : 'Read installed certificate IDs first';
            $('pnc-installed-id').appendChild(placeholder);
            certificates.forEach(c => {
                const option = document.createElement('option'); option.value = c.id;
                option.textContent = (typeLabels[c.certificateType] || c.certificateType) + ' · serial ' + c.certificateHashData.serialNumber;
                $('pnc-installed-id').appendChild(option);
                const tr = document.createElement('tr');
                cell(tr, typeLabels[c.certificateType] || c.certificateType); cell(tr, c.certificateHashData.serialNumber); cell(tr, c.certificateHashData.hashAlgorithm);
                $('pnc-inventory').appendChild(tr);
            });
            if (certificates.some(c => c.id === selected)) { $('pnc-installed-id').value = selected; }
            $('pnc-installed-id').disabled = certificates.length === 0;
            $('pnc-inventory-table').hidden = certificates.length === 0;
            $('pnc-inventory-status').textContent = !view.station ? 'Select a charge point to see its reported certificates.'
                : !view.queriedAt ? 'No certificate IDs have been read yet. Use Get Installed Certificate IDs to query this charge point.'
                : (certificates.length ? certificates.length + ' certificate ID(s) available. ' : 'No certificate IDs available. Read the charge point to refresh this list. ')
                    + 'Updated: ' + new Date(view.queriedAt).toLocaleString();
            preview();
        }
        async function refresh() {
            const response = await fetch(config.base + '/jobs');
            if (!response.ok) { throw new Error('Could not load jobs. Your session may have expired; reload and sign in again.'); }
            const jobs = await response.json();
            const latest = jobs.find(job => job.id === submittedJob);
            if (latest) {
                notice((labels[latest.message] || latest.message) + ' for ' + latest.station + ': '
                    + (states[latest.state] || latest.state) + '.', !['Pending', 'Succeeded', 'NotFound'].includes(latest.state));
            }
            $('pnc-jobs').replaceChildren();
            jobs.slice(-20).reverse().forEach(job => {
                const row = document.createElement('tr');
                cell(row, new Date(job.created).toLocaleString()); cell(row, job.station); cell(row, labels[job.message] || job.message);
                cell(row, states[job.state] || job.state); cell(row, job.outerStatus); cell(row, job.innerStatus); $('pnc-jobs').appendChild(row);
            });
            if (!jobs.length) { const row = document.createElement('tr'); cell(row, 'No recent jobs.'); row.firstChild.colSpan = 6; $('pnc-jobs').appendChild(row); }
            await readInventory();
            if (timer) { clearTimeout(timer); timer = null; }
            if (budget > 0 || jobs.some(j => j.state === 'Pending')) {
                budget = Math.max(0, budget - 1);
                timer = setTimeout(() => refresh().catch(e => notice(e.message, true)), 2500);
            }
        }
        async function send(message) {
            if (busy) { return; }
            try {
                const input = fields();
                if (!input.station) { throw new Error('Select a charge point first.'); }
                const data = payload(message, input, certificates);
                busy = true; $('pnc-submit').disabled = true; $('pnc-read-certificates').disabled = true;
                const headers = {'Content-Type':'application/json'}; headers[config.csrfHeader] = config.csrfToken;
                const response = await fetch(config.base + '/commands', {method:'POST', headers,
                    body:JSON.stringify({station:input.station, message, data:JSON.stringify(data)})});
                if (!response.ok) { throw new Error('Command could not be sent (HTTP ' + response.status + '). Check the fields or sign in again.'); }
                const job = await response.json();
                submittedJob = job.id;
                notice(labels[message] + ' sent to ' + input.station + '. ' + (states[job.state] || job.state) + '.', !['Pending', 'Succeeded', 'NotFound'].includes(job.state));
                budget = 24; await refresh();
            } catch (e) { notice(e.message, true); }
            finally { busy = false; $('pnc-submit').disabled = !config.enabled; $('pnc-read-certificates').disabled = !config.enabled; }
        }
        $('pnc-command').onsubmit = e => { e.preventDefault(); send($('pnc-message').value); };
        $('pnc-read-certificates').onclick = () => {
            const saved = $('pnc-query-type').value; $('pnc-query-type').value = '';
            const promise = send('GetInstalledCertificateIds'); $('pnc-query-type').value = saved; return promise;
        };
        $('pnc-refresh').onclick = () => refresh().catch(e => notice(e.message, true));
        document.querySelectorAll('[data-pnc-operation]').forEach(a => a.addEventListener('click', () => operation(a.dataset.pncOperation)));
        window.addEventListener('hashchange', () => operation(location.hash.slice(1)));
        $('pnc-station').onchange = () => {
            clearNotice();
            renderInventory({station:'', queriedAt:null, certificates:[]});
            try { localStorage.setItem('pnc-station', $('pnc-station').value); } catch (e) { /* Optional preference. */ }
            readInventory().catch(e => notice(e.message, true));
        };
        $('pnc-certificate-type').onchange = () => {
            $('pnc-root-purpose').textContent = $('pnc-certificate-type').value === 'MORootCertificate'
                ? 'Trust root for the lab EV contract certificates.' : 'Trust root for V2G / SECC certificate chains.';
            preview();
        };
        ['pnc-certificate', 'pnc-query-type', 'pnc-installed-id'].forEach(id => $(id).addEventListener('input', preview));
        $('pnc-certificate-file').onchange = async () => {
            const file = $('pnc-certificate-file').files[0]; if (!file) { return; }
            try {
                if (file.size > 16384) { throw new Error('Choose a PEM certificate file of at most 16 KiB.'); }
                const text = await file.text();
                payload('InstallCertificate', {...fields(), certificate:text}, []);
                $('pnc-certificate').value = text.replace(/\r\n?/g, '\n');
                clearNotice();
                $('pnc-file-status').textContent = 'Loaded ' + file.name; preview();
            } catch (e) { notice(e.message, true); }
        };
        $('pnc-use-lab-root').onclick = async () => {
            try {
                const requestedType = $('pnc-certificate-type').value;
                const response = await fetch(config.base + '/lab-roots');
                if (!response.ok) { throw new Error('Could not load lab root certificates.'); }
                const roots = await response.json(), found = roots.find(r => r.certificateType === requestedType);
                if (!found) { throw new Error('No lab root is configured for this certificate type.'); }
                if ($('pnc-certificate-type').value !== requestedType) { return; }
                $('pnc-certificate').value = found.certificate;
                clearNotice();
                $('pnc-file-status').textContent = 'Loaded the configured lab ' + typeLabels[requestedType] + '.'; preview();
            } catch (e) { notice(e.message, true); }
        };
        try { const saved = localStorage.getItem('pnc-station'); if (Array.from($('pnc-station').options).some(o => o.value === saved)) { $('pnc-station').value = saved; } } catch (e) { /* Optional preference. */ }
        $('pnc-submit').disabled = !config.enabled; $('pnc-read-certificates').disabled = !config.enabled;
        operation(location.hash.slice(1)); refresh().catch(e => notice(e.message, true));
    }
    const api = {payload, mount};
    if (typeof module !== 'undefined' && module.exports) { module.exports = api; }
    else { root.PncUI = api; }
})(typeof window !== 'undefined' ? window : globalThis);
