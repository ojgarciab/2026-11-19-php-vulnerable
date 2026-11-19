// Pruebas mínimas del analizador: node test/analyzer.test.js
const assert = require('node:assert/strict');
const A = require('../docs/js/analyzer.js');
const LOCALES = ['es', 'en'];
for (const c of LOCALES) A.registerLocale(c, require('../docs/js/locale-' + c + '.js'));

// Valores INI
assert.equal(A.iniBool('Off'), false);
assert.equal(A.iniBool('"1"'), true);
assert.equal(A.iniBool(''), false);
assert.equal(A.iniBytes('128M'), 128 * 1024 * 1024);
assert.equal(A.iniBytes('-1'), Infinity);

// Parser: comentarios inline y última aparición prevalece
const ini = [
  '[PHP]',
  'expose_php = On ; comentario',
  'session.serialize_handler = php',
  'session.serialize_handler = "php_serialize"',
  ';session.upload_progress.enabled = On',
  '[HOST=www.example.com]',
  'session.upload_progress.enabled = On',
].join('\n');
const parsed = A.parse(ini);
assert.equal(parsed.entries[1].value, 'On');
assert.equal(parsed.entries[1].comment, '; comentario');
assert.equal(parsed.entries[4].commentedKey, 'session.upload_progress.enabled');

const find = (res, k) => res.findings.find((f) => f.key === k);
const res = A.analyze(ini, { version: '8.3' });
assert.equal(find(res, 'session.upload_progress.enabled').status, 'add');
assert.deepEqual(find(res, 'session.upload_progress.enabled').conditionalLines, [7]);
assert.equal(find(res, 'session.serialize_handler').status, 'info');
assert.equal(find(res, 'session.serialize_handler').line, 4);
assert.equal(find(res, 'expose_php').status, 'change');
assert.equal(res.versionInfo.target, A.FIXED_VERSIONS['8.3']);
assert.equal(res.versionInfo.target, '8.3.37');
assert.equal(A.RELEASE_CONFIRMED, true);
assert.equal(A.analyze(ini, { version: '8.1' }).versionInfo.kind, 'eol');
// Directivas exclusivas de 8.5
assert.equal(find(res, 'fatal_error_backtraces').status, 'skip');
assert.equal(find(res, 'zend.exception_ignore_args').status, 'skip');
const r85 = A.analyze(ini, { version: '8.5' });
assert.equal(find(r85, 'fatal_error_backtraces').status, 'add');
assert.equal(find(r85, 'zend.exception_ignore_args').status, 'add');
assert.equal(find(A.analyze('zend.exception_ignore_args=Off', { version: '8.5' }), 'zend.exception_ignore_args').status, 'change');
assert.equal(find(A.analyze(ini), 'fatal_error_backtraces').status, 'info');
// error_log: solo se revisa si apunta a un fichero
assert.equal(find(res, 'error_log').status, 'ok');
assert.equal(find(A.analyze('error_log = /var/log/php.log'), 'error_log').status, 'info');
assert.equal(find(A.analyze('error_log = syslog'), 'error_log').status, 'ok');
// cgi.fix_pathinfo: sugerencia opcional
assert.equal(find(res, 'cgi.fix_pathinfo').status, 'info');
assert.equal(find(A.analyze('cgi.fix_pathinfo=0'), 'cgi.fix_pathinfo').status, 'ok');
// Todas las reglas referencian CVE conocidos
for (const r of A.RULES) for (const c of r.cves) assert.ok(A.CVES[c] && /^GHSA-/.test(A.CVES[c].ghsa), r.key + ': ' + c);

// Anotación: la salida debe ser un php.ini válido con los valores sugeridos como última aparición
const { output } = A.annotate(ini, { version: '8.3', date: '2026-11-19' });
const re = A.parse(output);
const last = (k) => [...re.entries].reverse().find((e) => e.type === 'directive' && e.key === k && !/^(PATH|HOST)=/i.test(e.section || ''));
assert.equal(last('session.upload_progress.enabled').value, 'Off');
assert.equal(last('expose_php').value, 'Off');
// La regla de revisión no modifica el valor original
assert.equal(last('session.serialize_handler').value, '"php_serialize"');
assert.ok(output.includes(';;OLD expose_php = On ; comentario'));
assert.ok(output.includes('ATENCIÓN ' + A.TAG));
assert.ok(output.includes('CVE-2026-115560 (GHSA-658j-r8rw-q6mx)'));
assert.ok(output.includes('CVE-2026-126714 (GHSA-fm2m-fjf5-v3cp)'));
// La directiva ausente se inserta bajo su versión comentada y antes de [HOST=...]
const lines = output.split('\n');
const ci = lines.indexOf(';session.upload_progress.enabled = On');
const di = lines.indexOf('session.upload_progress.enabled = Off');
assert.ok(ci >= 0 && di > ci && di < lines.indexOf('[HOST=www.example.com]'), 'debe insertarse bajo la línea comentada');

// Fichero ya seguro: sin manejador definido (por defecto php) y progreso de subida desactivado
const safe = ['session.upload_progress.enabled=0', 'expose_php=Off', 'fatal_error_backtraces=0', 'zend.exception_ignore_args=On', 'cgi.fix_pathinfo=0', 'error_log=syslog'].join('\n');
const r2 = A.analyze(safe, { version: '8.5' });
assert.ok(r2.findings.every((f) => f.status === 'ok'), 'no debería haber cambios');
for (const v of ['php_binary', 'PHP_SERIALIZE']) {
  assert.equal(find(A.analyze('session.serialize_handler=' + v), 'session.serialize_handler').status, 'info', v);
}

// CRLF se conserva
const crlf = A.annotate('expose_php = On\r\n', { version: 'unknown', date: '2026-11-19' }).output;
assert.ok(/\r\n/.test(crlf) && !/[^\r]\n/.test(crlf));

// Idiomas: mismas claves que el español y anotación completa sin errores
const en = A.annotate(ini, { version: '8.3', locale: 'en', date: '2026-11-19' });
assert.ok(en.output.includes('SUGGESTED CHANGE [LOW]'));
assert.ok(!en.output.includes('CAMBIO SUGERIDO'));
const keys = (o, p) => Object.keys(o).flatMap((k) => (o[k] && typeof o[k] === 'object' && !Array.isArray(o[k]) ? keys(o[k], p + k + '.') : [p + k]));
for (const code of LOCALES) {
  const L = A.getLocale(code);
  for (const r of A.RULES) assert.ok(L.rules[r.key] && L.rules[r.key].why && L.rules[r.key].caveat && L.rules[r.key].details, code + ': ' + r.key);
  for (const id of Object.keys(A.CVES)) assert.ok(L.cves[id] && L.cves[id].title, code + ': ' + id);
  assert.deepEqual(keys(L, '').sort(), keys(A.getLocale('es'), '').sort(), code + ': claves distintas al español');
  const o = A.annotate(ini, { version: '8.5', locale: code, date: '2026-11-19' }).output;
  const l = [...A.parse(o).entries].reverse().find((e) => e.type === 'directive' && e.key === 'expose_php');
  assert.equal(l.value, 'Off', code);
}

console.log('OK: todas las pruebas pasan (' + LOCALES.join(', ') + ')');
