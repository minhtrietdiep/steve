const {test} = require('node:test');
const assert = require('node:assert/strict');
const {payload} = require('../../main/webapp/static/js/pnc.js');

test('PEM paste normalizes line endings and produces the exact wrapped payload', () => {
    const value = payload('InstallCertificate', {certificateType:'V2GRootCertificate', certificate:'-----BEGIN CERTIFICATE-----\r\nAQID\r\n-----END CERTIFICATE-----\r\n'}, []);
    assert.equal(value.certificateType, 'V2GRootCertificate');
    assert.equal(JSON.parse(JSON.stringify(value)).certificate, '-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n');
    assert.throws(() => payload('InstallCertificate', {certificateType:'V2GRootCertificate', certificate:'-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----'}, []));
});

test('deletion can only select certificate hashes belonging to the chosen station', () => {
    const hash = {hashAlgorithm:'SHA256',issuerNameHash:'ab'.repeat(32),issuerKeyHash:'cd'.repeat(32),serialNumber:'01'};
    const certificates = [{id:'known', station:'station-a',certificateHashData:hash}];
    assert.deepEqual(payload('DeleteCertificate', {station:'station-a',certificateId:'known'}, certificates), {certificateHashData:hash});
    assert.throws(() => payload('DeleteCertificate', {station:'station-b',certificateId:'known'}, certificates));
    assert.throws(() => payload('DeleteCertificate', {station:'station-a',certificateId:''}, certificates));
});

test('list and trigger operations use the adapted v1.0 fields', () => {
    assert.deepEqual(payload('GetInstalledCertificateIds', {queryType:''}, []), {});
    assert.deepEqual(payload('GetInstalledCertificateIds', {queryType:'MORootCertificate'}, []), {certificateType:['MORootCertificate']});
    assert.deepEqual(payload('TriggerMessage', {}, []), {});
});
