/*
 * Analizador de php.ini para las mitigaciones de la publicación de seguridad
 * de PHP del 19/11/2026 (8.5.13 / 8.4.28 / 8.3.37 / 8.2.36).
 *
 * Módulo sin dependencias, ejecutable en navegador (window.PhpIniAnalyzer)
 * y en Node.js (module.exports). Los textos se cargan desde los ficheros
 * de idioma js/locale-*.js, que se registran con registerLocale().
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.PhpIniAnalyzer = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // Etiqueta que identifica el incidente en los comentarios del php.ini generado.
  const TAG = 'PHP-2026-11';

  // Versiones publicadas el 19/11/2026.
  const FIXED_VERSIONS = { '8.5': '8.5.13', '8.4': '8.4.28', '8.3': '8.3.37', '8.2': '8.2.36' };
  const RELEASE_CONFIRMED = true;

  // Vulnerabilidades críticas de la publicación y las que tienen mitigación en php.ini.
  // La lista completa (17 avisos) está en el README.
  const CVES = {
    'CVE-2026-115560': { id: 'CVE-2026-115560', ghsa: 'GHSA-658j-r8rw-q6mx', cvss: '9.2' },
    'CVE-2026-126714': { id: 'CVE-2026-126714', ghsa: 'GHSA-fm2m-fjf5-v3cp', cvss: '9.2' },
    'CVE-2026-129289': { id: 'CVE-2026-129289', ghsa: 'GHSA-qc49-hpvq-g2w6', cvss: '9.2' },
    'CVE-2026-129496': { id: 'CVE-2026-129496', ghsa: 'GHSA-gr4f-wgx5-jpfv', cvss: '9.2' },
    'CVE-2026-129481': { id: 'CVE-2026-129481', ghsa: 'GHSA-g3vh-838c-65v7', cvss: '9.2' },
    'CVE-2026-129474': { id: 'CVE-2026-129474', ghsa: 'GHSA-8mjj-2r7p-4hg2', cvss: '9.2' },
    'CVE-2026-129182': { id: 'CVE-2026-129182', ghsa: 'GHSA-2fjv-p558-g82m', cvss: '9.2' },
    'CVE-2026-129538': { id: 'CVE-2026-129538', ghsa: 'GHSA-5j3f-64r7-f564', cvss: '6.9' },
  };

  const locales = {};
  function registerLocale(code, data) { locales[code] = data; }
  function getLocale(code) {
    const l = locales[code] || locales.es || locales[Object.keys(locales)[0]];
    if (!l) throw new Error('No locale registered');
    return l;
  }

  /* ------------------------------------------------------------------ */
  /* Utilidades de valores INI                                           */
  /* ------------------------------------------------------------------ */

  function stripQuotes(v) {
    v = v.trim();
    if (v.length >= 2 && ((v[0] === '"' && v[v.length - 1] === '"') || (v[0] === "'" && v[v.length - 1] === "'"))) {
      return v.slice(1, -1);
    }
    return v;
  }

  function iniBool(v) {
    if (v === undefined || v === null) return null;
    const s = stripQuotes(String(v)).toLowerCase();
    if (['1', 'on', 'yes', 'true'].includes(s)) return true;
    if (['0', 'off', 'no', 'false', 'none', ''].includes(s)) return false;
    const n = Number(s);
    if (!Number.isNaN(n)) return n !== 0;
    return null;
  }

  function iniBytes(v) {
    if (v === undefined || v === null) return null;
    const s = stripQuotes(String(v)).trim();
    if (s === '') return null;
    const m = /^(-?\d+)\s*([kmg]?)$/i.exec(s);
    if (!m) return null;
    let n = parseInt(m[1], 10);
    if (n < 0) return Infinity;
    const unit = m[2].toLowerCase();
    if (unit === 'k') n *= 1024;
    else if (unit === 'm') n *= 1024 * 1024;
    else if (unit === 'g') n *= 1024 * 1024 * 1024;
    return n;
  }

  function iniInt(v) {
    if (v === undefined || v === null) return null;
    const s = stripQuotes(String(v)).trim();
    if (!/^-?\d+$/.test(s)) return null;
    return parseInt(s, 10);
  }

  function fmtBytes(n, L) {
    if (n === Infinity) return L.bytes.unlimited;
    if (n === null) return L.bytes.unknown;
    if (n % (1024 * 1024 * 1024) === 0) return n / (1024 * 1024 * 1024) + 'G';
    if (n % (1024 * 1024) === 0) return n / (1024 * 1024) + 'M';
    if (n % 1024 === 0) return n / 1024 + 'K';
    return n + ' bytes';
  }

  /* ------------------------------------------------------------------ */
  /* Parser línea a línea (conserva comentarios y orden)                 */
  /* ------------------------------------------------------------------ */

  function splitValueComment(raw) {
    let inQ = null;
    for (let i = 0; i < raw.length; i++) {
      const c = raw[i];
      if (inQ) {
        if (c === inQ) inQ = null;
      } else if (c === '"' || c === "'") {
        inQ = c;
      } else if (c === ';') {
        return { value: raw.slice(0, i).trim(), comment: raw.slice(i) };
      }
    }
    return { value: raw.trim(), comment: '' };
  }

  function parse(text) {
    const lines = text.split(/\r?\n/);
    const eol = /\r\n/.test(text) ? '\r\n' : '\n';
    const entries = [];
    let section = null;
    lines.forEach((line, idx) => {
      const t = line.trim();
      const entry = { index: idx, raw: line, type: 'other', section };
      if (t === '') {
        entry.type = 'blank';
      } else if (t[0] === ';' || t[0] === '#') {
        entry.type = 'comment';
        const m = /^[;#]\s*([A-Za-z_][\w.]*)\s*=\s*(.*)$/.exec(t);
        if (m) {
          entry.commentedKey = m[1].toLowerCase();
          entry.commentedValue = splitValueComment(m[2]).value;
        }
      } else if (t[0] === '[') {
        entry.type = 'section';
        const m = /^\[([^\]]*)\]/.exec(t);
        section = m ? m[1].trim() : t;
        entry.section = section;
        entry.name = section;
      } else {
        const eq = t.indexOf('=');
        if (eq > 0) {
          const key = t.slice(0, eq).trim();
          const { value, comment } = splitValueComment(t.slice(eq + 1));
          entry.type = 'directive';
          entry.key = key.toLowerCase();
          entry.originalKey = key;
          entry.value = value;
          entry.comment = comment;
        }
      }
      entries.push(entry);
    });
    return { entries, eol };
  }

  function isConditionalSection(name) {
    return !!name && /^(PATH|HOST)\s*=/i.test(name);
  }

  function findDirective(parsed, key) {
    let found = null;
    for (const e of parsed.entries) {
      if (e.type === 'directive' && e.key === key && !isConditionalSection(e.section)) found = e;
    }
    return found;
  }

  function findConditional(parsed, key) {
    return parsed.entries.filter((e) => e.type === 'directive' && e.key === key && isConditionalSection(e.section));
  }

  /* ------------------------------------------------------------------ */
  /* Reglas (la lógica aquí; los textos en los ficheros de idioma)       */
  /* ------------------------------------------------------------------ */

  // check() devuelve { status, msg?, params? }; msg es la clave del texto en el idioma.
  // Directivas que solo existen o solo son explotables en PHP 8.5.
  function only85(ctx) {
    if (ctx.version && ctx.version !== '8.5' && ctx.version !== 'unknown') return { status: 'skip', msg: 'skip' };
    if (!ctx.present) return ctx.version === '8.5' ? { status: 'add', msg: 'add' } : { status: 'info', msg: 'info' };
    return null;
  }

  const RULES = [
    {
      key: 'session.upload_progress.enabled', cves: ['CVE-2026-115560', 'CVE-2026-126714'], severity: 'critica', suggested: 'Off', scope: 'PHP_INI_PERDIR',
      check(ctx) {
        if (!ctx.present) return { status: 'add', msg: 'add' };
        if (iniBool(ctx.value) === false) return { status: 'ok' };
        return { status: 'change', msg: 'change', params: { value: ctx.value } };
      },
    },
    {
      // El desajuste de serializadores también puede darse entre aplicaciones, pools o
      // tareas CLI que comparten almacén de sesiones: no se puede comprobar desde un
      // único php.ini, así que solo se pide revisarlo.
      key: 'session.serialize_handler', cves: ['CVE-2026-115560'], severity: 'alta', suggested: 'php', scope: 'PHP_INI_ALL',
      check(ctx) {
        if (!ctx.present) return { status: 'ok' };
        const v = stripQuotes(ctx.value).toLowerCase();
        if (v === 'php_binary' || v === 'php_serialize') return { status: 'info', msg: 'info', params: { value: ctx.value } };
        return { status: 'ok' };
      },
    },
    {
      key: 'fatal_error_backtraces', cves: ['CVE-2026-129182', 'CVE-2026-129474'], severity: 'critica', suggested: 'Off', scope: 'PHP_INI_ALL',
      check(ctx) {
        const r = only85(ctx);
        if (r) return r;
        if (iniBool(ctx.value) === false) return { status: 'ok' };
        return { status: 'change', msg: 'change', params: { value: ctx.value } };
      },
    },
    {
      key: 'zend.exception_ignore_args', cves: ['CVE-2026-129474'], severity: 'critica', suggested: 'On', scope: 'PHP_INI_ALL',
      check(ctx) {
        const r = only85(ctx);
        if (r) return r;
        if (iniBool(ctx.value) === true) return { status: 'ok' };
        return { status: 'change', msg: 'change', params: { value: ctx.value } };
      },
    },
    {
      // Solo se revisa si error_log apunta a un fichero: sin definir (stderr / log del
      // SAPI) o con syslog no se alcanza la ruta vulnerable del aviso.
      key: 'error_log', cves: ['CVE-2026-129496'], severity: 'alta', suggested: 'syslog', scope: 'PHP_INI_ALL',
      check(ctx) {
        if (!ctx.present) return { status: 'ok' };
        const v = stripQuotes(ctx.value).toLowerCase();
        if (v === '' || v === 'syslog') return { status: 'ok' };
        return { status: 'info', msg: 'info', params: { value: ctx.value } };
      },
    },
    {
      key: 'cgi.fix_pathinfo', cves: ['CVE-2026-129538'], severity: 'media', suggested: '0', scope: 'PHP_INI_SYSTEM',
      check(ctx) {
        if (!ctx.present) return { status: 'info', msg: 'infoAbsent' };
        if (iniBool(ctx.value) === false) return { status: 'ok' };
        return { status: 'info', msg: 'infoOn' };
      },
    },
    {
      key: 'expose_php', cves: [], severity: 'baja', suggested: 'Off', scope: 'PHP_INI_SYSTEM',
      check(ctx) {
        if (!ctx.present) return { status: 'add', msg: 'add' };
        if (iniBool(ctx.value) === false) return { status: 'ok' };
        return { status: 'change', msg: 'change', params: { value: ctx.value } };
      },
    },
  ];

  function tpl(str, params) {
    return String(str || '').replace(/\{(\w+)\}/g, (m, k) => (params && k in params ? params[k] : m));
  }

  /* ------------------------------------------------------------------ */
  /* Análisis                                                            */
  /* ------------------------------------------------------------------ */

  function analyze(text, options) {
    options = options || {};
    const version = options.version || 'unknown';
    const L = getLocale(options.locale);
    const parsed = parse(text);
    const findings = [];

    for (const rule of RULES) {
      const entry = findDirective(parsed, rule.key);
      const conditional = findConditional(parsed, rule.key);
      const r = rule.check({ present: !!entry, value: entry ? entry.value : undefined, version, L });
      const T = L.rules[rule.key];
      findings.push({
        key: rule.key,
        cve: rule.cves[0] || null,
        cves: rule.cves,
        severity: rule.severity,
        category: T.category,
        suggested: rule.suggested,
        scope: rule.scope,
        why: T.why,
        caveat: T.caveat,
        status: r.status,
        detail: r.msg ? tpl(T.details[r.msg], r.params) : '',
        line: entry ? entry.index + 1 : null,
        current: entry ? entry.value : null,
        conditionalLines: conditional.map((e) => e.index + 1),
        entry,
      });
    }

    return { parsed, findings, version, versionInfo: versionAdvice(version, L), locale: L };
  }

  function versionAdvice(version, L) {
    if (FIXED_VERSIONS[version]) {
      const text = RELEASE_CONFIRMED ? L.version.supported : L.version.supportedPending;
      return { kind: 'supported', target: FIXED_VERSIONS[version], text: tpl(text, { target: FIXED_VERSIONS[version] }) };
    }
    if (['7.4', '8.0', '8.1'].includes(version)) {
      return { kind: 'eol', target: null, text: tpl(L.version.eol, { version }) };
    }
    if (version === 'old') return { kind: 'eol', target: null, text: L.version.old };
    return { kind: 'unknown', target: null, text: RELEASE_CONFIRMED ? L.version.unknown : L.version.unknownPending };
  }

  /* ------------------------------------------------------------------ */
  /* Generación del php.ini anotado                                      */
  /* ------------------------------------------------------------------ */

  function wrap(text, width, prefix) {
    const words = text.split(/\s+/);
    const out = [];
    let line = '';
    for (const w of words) {
      if ((line + ' ' + w).trim().length > width) {
        out.push(prefix + line.trim());
        line = w;
      } else {
        line = (line + ' ' + w).trim();
      }
    }
    if (line) out.push(prefix + line.trim());
    return out;
  }

  function annotate(text, options) {
    const result = analyze(text, options);
    const { parsed, findings, version, versionInfo } = result;
    const L = result.locale;
    const A = L.annotate;
    const eol = parsed.eol;
    const out = [];
    const today = (options && options.date) || new Date().toISOString().slice(0, 10);

    function commentBlock(f, action) {
      const lines = [];
      lines.push(';; --- ' + TAG + ': ' + action + ' [' + L.severity[f.severity] + '] ---');
      for (const c of f.cves) lines.push(';; ' + c + ' (' + CVES[c].ghsa + ')');
      if (f.detail) lines.push(...wrap(A.reason + ' ' + f.detail, 76, ';; '));
      lines.push(...wrap(f.why, 76, ';; '));
      lines.push(...wrap(A.caution + ' ' + f.caveat, 76, ';; '));
      return lines;
    }

    const rule = ';; ==========================================================================';
    out.push(rule);
    for (const l of A.header) out.push(';; ' + l);
    out.push(';; ' + tpl(A.generated, { date: today, version: version === 'unknown' ? A.versionNotGiven : version }));
    out.push(';;');
    out.push(...wrap(versionInfo.text, 76, ';; '));
    out.push(';;');
    for (const l of A.disclaimer) out.push(';; ' + l);
    out.push(rule);
    out.push('');

    const byLine = new Map();
    for (const f of findings) if (f.entry) byLine.set(f.entry.index, f);

    const pending = findings.filter((f) => !f.entry && (f.status === 'add' || f.status === 'info'));
    const placed = new Set();

    function addedBlock(f) {
      const block = [];
      if (f.status === 'add') {
        block.push(...commentBlock(f, A.actionAdded));
        block.push(f.key + ' = ' + f.suggested);
      } else {
        block.push(...commentBlock(f, A.actionOptional));
        block.push(';' + f.key + ' = ' + f.suggested);
      }
      block.push(A.end);
      return block;
    }

    const firstCond = parsed.entries.findIndex((e) => e.type === 'section' && isConditionalSection(e.name));
    let condInsertPos = -1;

    for (const e of parsed.entries) {
      if (e.index === firstCond) condInsertPos = out.length;
      const f = byLine.get(e.index);
      if (!f) {
        out.push(e.raw);
        if (e.type === 'comment' && e.commentedKey && !isConditionalSection(e.section)) {
          const pf = pending.find((x) => x.key === e.commentedKey && !placed.has(x.key));
          if (pf) {
            placed.add(pf.key);
            out.push(...addedBlock(pf));
          }
        }
        continue;
      }
      if (f.status === 'ok') {
        out.push(e.raw + ' ' + A.okInline);
      } else if (f.status === 'change') {
        out.push(...commentBlock(f, A.actionChange));
        out.push(';;OLD ' + e.raw);
        out.push(e.originalKey + ' = ' + f.suggested);
        out.push(A.end);
      } else if (f.status === 'info') {
        out.push(...commentBlock(f, A.actionReview));
        out.push(';; ' + A.suggestionIfApplicable + ' ' + e.originalKey + ' = ' + f.suggested);
        out.push(e.raw);
        out.push(A.end);
      } else {
        out.push(e.raw);
      }
    }

    const toAdd = pending.filter((f) => !placed.has(f.key));
    if (toAdd.length) {
      const block = [''];
      block.push(rule);
      for (const l of A.missingHeader) block.push(';; ' + l);
      block.push(rule);
      for (const f of toAdd) {
        block.push('');
        block.push(...addedBlock(f));
      }
      const lastSection = [...parsed.entries].reverse().find((e) => e.type === 'section');
      if (lastSection && isConditionalSection(lastSection.name) && condInsertPos >= 0) {
        out.splice(condInsertPos, 0, ...block, '');
      } else {
        out.push(...block);
      }
    }

    const cond = findings.filter((f) => f.conditionalLines.length);
    if (cond.length) {
      out.push('');
      for (const l of A.conditionalWarning) out.push(';; ' + l);
      for (const f of cond) out.push(';;   ' + tpl(A.conditionalLine, { key: f.key, lines: f.conditionalLines.join(', ') }));
    }

    out.push('');
    for (const l of A.footer) out.push(';; ' + l);

    let output = out.join(eol);
    if (!output.endsWith(eol)) output += eol;
    return { output, result };
  }

  return { parse, analyze, annotate, iniBool, iniBytes, iniInt, fmtBytes, registerLocale, getLocale, RULES, CVES, FIXED_VERSIONS, RELEASE_CONFIRMED, TAG };
});
