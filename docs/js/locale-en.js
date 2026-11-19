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
      advisoryPending: 'full advisory not yet published',
      caution: 'Caution:',
      scope: 'Scope:',
      downloadSuffix: '.php-2026-11-annotated.ini',
    },
    cves: {
      'CVE-2026-115560': {
        title: 'Remote code execution through session upload progress (session.upload_progress)',
        summary:
          'If the server sets session.serialize_handler to php_binary or php_serialize and the ' +
          'application switches it to php at runtime with ini_set() before session_start(), session ' +
          'upload progress writes the data with one handler and the application reads it with another. ' +
          'That mismatch allows objects to be injected into the session and can lead to remote code ' +
          'execution. PHP considers it unlikely: it needs that non-default configuration, that ' +
          'application code and session.upload_progress enabled, all at once.',
      },
    },
    version: {
      supported: 'Upgrade to PHP {target} (or later) as soon as possible. The php.ini mitigations are temporary and partial.',
      supportedPending:
        'The fix ships on 2026-11-19 (14:00-14:30 UTC), expected as PHP {target}: confirm the number ' +
        'against the official announcement and upgrade as soon as it is available. Until then apply ' +
        'the php.ini mitigations, which are temporary and partial.',
      eol:
        'PHP {version} is end-of-life: there will be no official fixed release. You depend on the ' +
        'patches your distribution backports (Debian, Ubuntu, RHEL), which keep the version number: ' +
        'check the package changelog, not php -v. Keep the mitigation permanently and plan the ' +
        'migration to PHP 8.3+ (8.2 only receives security fixes until 2026-12-31).',
      old:
        'PHP 7.3 or earlier: no patch available at all. Apply the mitigations, isolate the service and ' +
        'migrate urgently to a supported branch (8.3 or 8.4 recommended).',
      unknown:
        'Fixed releases: 8.5.13, 8.4.28, 8.3.37 and 8.2.36. For 8.1 and earlier only distribution ' +
        'backports can be expected.',
      unknownPending:
        'The fixed releases ship on 2026-11-19 (14:00-14:30 UTC) for the 8.5, 8.4, 8.3 and 8.2 ' +
        'branches (expected 8.5.13, 8.4.28, 8.3.37 and 8.2.36; confirm against the official ' +
        'announcement). For 8.1 and earlier only distribution backports can be expected.',
    },
    annotate: {
      header: [
        'php.ini annotated automatically - PHP-2026-11 mitigations',
        'CVE-2026-115560 (PHP security release of 2026-11-19, highest severity critical)',
      ],
      generated: 'Generated on {date} - PHP version given: {version}',
      versionNotGiven: 'not given',
      disclaimer: [
        'These mitigations are TEMPORARY and PARTIAL. The only complete fix is to upgrade',
        'PHP to the release published on 2026-11-19 and restart PHP-FPM / Apache.',
        'Modified original lines are kept commented out with the ";;OLD" prefix.',
        'Review every change before applying it in production.',
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
      'session.upload_progress.enabled': {
        category: 'Mitigation recommended by PHP',
        why:
          'This is the mitigation PHP has recommended since its 2026-10-23 notice: with session upload ' +
          'progress disabled, the CVE-2026-115560 path cannot be reached. It is the same directive ' +
          'already recommended for CVE-2026-109619 (PHP2Shell): if you disabled it in October, keep it off.',
        caveat:
          'It is PHP_INI_PERDIR: do NOT rely on a .user.ini or an application ini_set() for this. On ' +
          'PHP-FPM also pin it in the pool with php_admin_flag[session.upload_progress.enabled] = off ' +
          'and restart ALL worker processes. Temporary mitigation: it does not replace the upgrade.',
        details: { add: 'Not set; the PHP default is On.', change: 'It is enabled ({value}).' },
      },
      'session.serialize_handler': {
        category: 'Exposure condition (review the code)',
        why:
          'A handler configured as php_binary or php_serialize is the first condition for ' +
          'CVE-2026-115560. The second one lives in the code: look for calls to ' +
          "ini_set('session.serialize_handler', 'php') made before session_start(). If both hold and " +
          'upload progress is still enabled, the installation is exploitable.',
        caveat:
          'Do not change the handler without testing: sessions already stored in another format will no ' +
          'longer be readable. What removes the mismatch is configuration and application always using ' +
          'the same handler (and never switching it at runtime). Also check conf.d/*.ini, the PHP-FPM ' +
          'pool, .htaccess and .user.ini, where it can be redefined.',
        details: { info: 'Configured as {value}: the first exposure condition is met.' },
      },
      expose_php: {
        category: 'General hardening',
        why:
          'Hides the X-Powered-By header with the exact PHP version, which mass scanners use to locate ' +
          'installations that have not been upgraded.',
        caveat: 'It does not mitigate the vulnerability; it only makes version fingerprinting harder.',
        details: { add: 'Not set (default On).', change: 'It is enabled ({value}).' },
      },
    },
  };
});
