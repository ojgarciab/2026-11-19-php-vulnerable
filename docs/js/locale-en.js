/* English texts for the analyzer and the user interface. */
(function (root, factory) {
  const data = factory();
  if (typeof module === 'object' && module.exports) module.exports = data;
  else root.PhpIniAnalyzer.registerLocale('en', data);
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';
  return {
    code: 'en',
    severity: { critica: 'CRITICAL', alta: 'HIGH', media: 'MEDIUM', baja: 'LOW' },
    status: { ok: 'OK', change: 'Change', add: 'Add', info: 'Review', skip: 'N/A' },
    bytes: { unlimited: 'unlimited (-1)', unknown: 'unknown' },
    ui: {
      noFile: 'No file selected',
      sampleLoaded: 'Sample loaded (php.ini-production)',
      emptyAlert: 'Load or paste the contents of a php.ini first.',
      copied: 'Copied ✓',
      copy: 'Copy to clipboard',
      clipboardError: 'Clipboard access failed; copy the text from the preview instead.',
      phpVersion: 'PHP version:',
      notDefined: 'not set',
      empty: '(empty)',
      alsoConditional: 'Also set inside [PATH=]/[HOST=] sections',
      vulnerabilities: 'Vulnerabilities',
      directives: 'Directives checked',
      phpAdvisory: 'PHP advisory:',
      caution: 'Caution:',
      scope: 'Scope:',
      downloadSuffix: '.php-2026-11-annotated.ini',
    },
    cves: {
      "CVE-2026-115560": {
        "title": "Session serializer mismatch can lead to remote code execution",
        "summary": "Session upload progress writes an attacker-controlled value into the session with the configured serializer (php_binary or php_serialize). If that same session is later read with the php serializer, the injected delimiters allow objects to be unserialized and, given a suitable gadget chain, code to run. The mismatch happens when the application changes session.serialize_handler before session_start(), or when separate applications, pools, virtual hosts or CLI jobs share a session store with different settings. Affects 8.2-8.5. The fix disables upload progress by default, but an explicit setting still enables it."
      },
      "CVE-2026-126714": {
        "title": "Partially overwritten session files can lead to remote code execution",
        "summary": "An interrupted session write with the files handler (the default) leaves a mixed file which, when unserialized, can run code if the application has a gadget chain. It requires attacker influence over session data (upload progress is one path). Affects 8.2-8.5. Disabling upload progress only closes that path."
      },
      "CVE-2026-129289": {
        "title": "PHP-FPM request smuggling through an unread HTTP request body",
        "summary": "If the web server reuses FastCGI connections (nginx fastcgi_keep_conn on, Apache mod_proxy_fcgi enablereuse=on, HAProxy, LSAPI) and the application opens php://input without reading it fully, the leftover bytes are parsed as a new FastCGI request: the attacker can run PHP as the worker. No memory corruption needed. Affects 8.2-8.5. It CANNOT be mitigated from php.ini: disable connection reuse in the web server and do not expose the PHP-FPM listener."
      },
      "CVE-2026-129496": {
        "title": "Timezone cache use-after-free can lead to remote code execution",
        "summary": "On non-thread-safe builds (PHP-FPM, mod_php), a diagnostic raised at startup and written through PHP's file-based error_log leaves a stale reference that the first request of each worker can reuse. Affects 8.2-8.5. Mitigation: fix the configuration errors and deprecated settings that raise startup diagnostics, or send errors to syslog, and restart the master and all workers."
      },
      "CVE-2026-129481": {
        "title": "Use-after-free after interrupted session shutdown",
        "summary": "If session cleanup ends in a fatal error (for example in the stream_close() of a user stream wrapper), the next request served by the same worker reuses freed memory. It is an incomplete fix for CVE-2026-109619. Affects 8.3-8.5 (not 8.2). It CANNOT be mitigated from php.ini or by disabling upload progress; on PHP-FPM, pm.max_requests = 1 prevents it at a high performance cost."
      },
      "CVE-2026-129474": {
        "title": "Use-after-free in magic method backtraces (PHP 8.5 only)",
        "summary": "With fatal_error_backtraces enabled and zend.exception_ignore_args disabled, a memory_limit fatal error during a __call()/__callStatic() call leaves freed memory reachable. PHP 8.5 only. php.ini-production already sets zend.exception_ignore_args = On, which prevents it; the built-in default is Off."
      },
      "CVE-2026-129182": {
        "title": "Use-after-free via repopulation of the last fatal error backtrace after shutdown (PHP 8.5 only)",
        "summary": "Incomplete fix for CVE-2026-109619: certain diagnostics raised during shutdown repopulate the fatal error backtrace and a later request on the same worker reuses it. PHP 8.5 only, with PHP-FPM or mod_php. Mitigation: fatal_error_backtraces = Off and restart all workers."
      },
      "CVE-2026-129538": {
        "title": "PHP-CGI out-of-bounds read and write during PATH_INFO correction",
        "summary": "Affects only the php-cgi binary (CGI and FastCGI modes), not PHP-FPM or mod_php, with cgi.fix_pathinfo = 1 (the default) and particular web server mappings. Causes crashes and memory disclosure; code execution is not confirmed. Affects 8.2-8.5."
      }
    },
    version: {
      "supported": "Upgrade to PHP {target} (or later) as soon as possible and restart every process. The php.ini mitigations are temporary and partial: several critical vulnerabilities in this release cannot be mitigated from php.ini.",
      "supportedPending": "Upgrade to PHP {target} as soon as it is available.",
      "eol": "PHP {version} is end-of-life: there is no official fixed release, and the advisories say older releases may be affected. You depend on the patches your distribution backports (Debian, Ubuntu, RHEL), which keep the version number: check the package changelog, not php -v. Keep the mitigations and plan the migration to PHP 8.3+ (8.2 only receives security fixes until 2026-12-31).",
      "old": "PHP 7.3 or earlier: no patch available at all. Apply the mitigations, isolate the service and migrate urgently to a supported branch (8.3 or 8.4 recommended).",
      "unknown": "Fixed releases (2026-11-19): 8.5.13, 8.4.28, 8.3.37 and 8.2.36. For 8.1 and earlier only distribution backports can be expected.",
      "unknownPending": "Fixed releases not yet published."
    },
    annotate: {
      header: [
        "php.ini annotated automatically - PHP-2026-11 mitigations",
        "PHP security release of 2026-11-19 (17 advisories, 7 critical, max CVSS 9.2)"
      ],
      generated: 'Generated on {date} - PHP version given: {version}',
      versionNotGiven: 'not given',
      disclaimer: [
        "These mitigations are TEMPORARY and PARTIAL. The only complete fix is to upgrade",
        "PHP (8.5.13 / 8.4.28 / 8.3.37 / 8.2.36) and restart PHP-FPM / Apache.",
        "CVE-2026-129289 (PHP-FPM) and CVE-2026-129481 can NOT be mitigated from php.ini.",
        "Modified original lines are kept commented out with the \";;OLD\" prefix.",
        "Review every change before applying it in production."
      ],
      reason: 'Reason:',
      caution: 'Caution:',
      actionChange: 'SUGGESTED CHANGE',
      actionAdded: 'DIRECTIVE ADDED',
      actionOptional: 'OPTIONAL SUGGESTION (commented out)',
      actionReview: 'OPTIONAL REVIEW (no change)',
      suggestionIfApplicable: 'Suggestion if applicable:',
      okInline: ';; PHP-2026-11: OK, value already safe',
      end: ';; --- end PHP-2026-11 ---',
      missingHeader: [
        'PHP-2026-11: directives NOT present in the original file',
        'Appended at the end: in php.ini the last occurrence of a directive wins.',
      ],
      conditionalWarning: [
        'PHP-2026-11 WARNING: the following directives are also redefined inside [PATH=...] /',
        '[HOST=...] sections and take precedence for those hosts/paths. Review them manually:',
      ],
      conditionalLine: '{key} on lines {lines}',
      footer: [
        'Final PHP-2026-11 reminder: after applying the changes restart ALL processes',
        '(systemctl restart php-fpm / apache2) and verify with php --ini and php -i.',
      ],
    },
    rules: {
      "session.upload_progress.enabled": {
        "category": "Mitigation recommended by PHP",
        "why": "With session upload progress disabled, the attack path of CVE-2026-115560 and one of the paths of CVE-2026-126714 are removed. The fixed releases disable it by default, but an explicit On re-enables it: check it AFTER upgrading too.",
        "caveat": "It must be disabled in EVERY configuration that writes to the same session store (php.ini, PHP-FPM pools, virtual hosts, CLI jobs). It is PHP_INI_PERDIR: an application ini_set() is too late. On PHP-FPM pin it with php_admin_flag[session.upload_progress.enabled] = off and restart all workers. It does not protect applications that store attacker-controlled data in sessions (CVE-2026-126714) and does not mitigate CVE-2026-129481.",
        "details": {
          "add": "Not set; on unfixed releases the default is On.",
          "change": "It is explicitly enabled ({value}); it stays enabled even after upgrading."
        }
      },
      "session.serialize_handler": {
        "category": "Exposure condition (review)",
        "why": "CVE-2026-115560 needs a session written with php_binary or php_serialize to be read with the php serializer. That happens when the application changes the handler before session_start(), but also when another application, pool, virtual host or CLI job with a different setting shares the same session store (PHP-FPM pools do not separate the store by themselves).",
        "caveat": "Do not change the handler without testing: when changing a store's format, migrate or expire the existing sessions instead of reading them with the new serializer. If applications need different formats, isolate their session store (session.save_path). After upgrading, PHP rejects runtime changes to session settings while upload progress is enabled.",
        "details": {
          "info": "Configured as {value}: check that everything reading this session store uses the same handler."
        }
      },
      "fatal_error_backtraces": {
        "category": "Mitigation recommended by PHP (PHP 8.5 only)",
        "why": "Disabling fatal error backtraces closes CVE-2026-129182 and CVE-2026-129474, two critical use-after-free bugs that only affect PHP 8.5. It was already a PHP2Shell mitigation: if you disabled it in October, keep it off.",
        "caveat": "The directive only exists in PHP 8.5. Set it administratively (php.ini or php_admin_flag in the pool) so no per-request configuration can re-enable it, and restart all workers. Changing only the CLI configuration is not enough.",
        "details": {
          "skip": "Only applies to PHP 8.5.",
          "add": "Not set; the default in 8.5 is On.",
          "info": "Only applies if you run PHP 8.5. Added commented out for reference.",
          "change": "It is enabled ({value})."
        }
      },
      "zend.exception_ignore_args": {
        "category": "Mitigation recommended by PHP (PHP 8.5 only)",
        "why": "With arguments excluded from backtraces the CVE-2026-129474 path cannot be reached. php.ini-production already sets it to On, but the built-in default is Off, so an installation without this line is exposed.",
        "caveat": "Exception backtraces will no longer include function arguments (the recommended production setting). Check the effective configuration of the workers, including PHP-FPM pools and application overrides. display_errors = Off does not prevent the vulnerability.",
        "details": {
          "skip": "Only exploitable on PHP 8.5.",
          "add": "Not set; the built-in default is Off.",
          "info": "Only exploitable on PHP 8.5. Added commented out for reference.",
          "change": "It is disabled ({value})."
        }
      },
      "error_log": {
        "category": "Exposure condition (review)",
        "why": "CVE-2026-129496 needs a diagnostic raised at startup to be written through PHP's file-based error_log. Sending errors to syslog avoids that path; PHP-FPM's own error log does not reach it either.",
        "caveat": "The main mitigation is to fix the configuration errors and deprecated settings that raise startup diagnostics (an invalid date.timezone, for example): check the log after restarting. If you switch to syslog, make sure your log collection handles it. Restart the master and all workers.",
        "details": {
          "info": "Errors are written to a file ({value})."
        }
      },
      "cgi.fix_pathinfo": {
        "category": "Attack surface reduction (php-cgi only, optional)",
        "why": "With cgi.fix_pathinfo = 0 the vulnerable PATH_INFO correction of CVE-2026-129538 does not run. It only affects the php-cgi binary (CGI and FastCGI); PHP-FPM and mod_php are not vulnerable to this bug.",
        "caveat": "OPTIONAL: it can break routing in applications that depend on PATH_INFO; test first. If you do not use php-cgi you do not need it. Also restrict direct access to FastCGI listeners.",
        "details": {
          "infoAbsent": "Not set (default 1). Added commented out for you to decide.",
          "infoOn": "It is enabled. A commented-out suggestion is added for you to decide."
        }
      },
      "expose_php": {
        "category": "General hardening",
        "why": "Hides the X-Powered-By header with the exact PHP version, which mass scanners use to locate installations that have not been upgraded.",
        "caveat": "It does not mitigate any vulnerability; it only makes version fingerprinting harder.",
        "details": {
          "add": "Not set (default On).",
          "change": "It is enabled ({value})."
        }
      }
    },
  };
});
