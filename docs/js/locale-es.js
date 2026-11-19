/* Textos en español para el analizador y la interfaz. */
(function (root, factory) {
  const data = factory();
  if (typeof module === 'object' && module.exports) module.exports = data;
  else root.PhpIniAnalyzer.registerLocale('es', data);
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';
  return {
    code: 'es',
    severity: { critica: 'CRÍTICA', alta: 'ALTA', media: 'MEDIA', baja: 'BAJA' },
    status: { ok: 'OK', change: 'Cambiar', add: 'Añadir', info: 'Revisar', skip: 'No aplica' },
    bytes: { unlimited: 'sin límite (-1)', unknown: 'desconocido' },
    ui: {
      noFile: 'Ningún fichero seleccionado',
      sampleLoaded: 'Ejemplo cargado (php.ini-production)',
      emptyAlert: 'Carga o pega primero el contenido de un php.ini.',
      copied: 'Copiado ✓',
      copy: 'Copiar al portapapeles',
      clipboardError: 'No se pudo acceder al portapapeles; copia el texto de la vista previa.',
      phpVersion: 'Versión de PHP:',
      notDefined: 'no definida',
      empty: '(vacío)',
      alsoConditional: 'También definida en secciones [PATH=]/[HOST=]',
      vulnerabilities: 'Vulnerabilidades',
      directives: 'Directivas analizadas',
      phpAdvisory: 'Aviso de PHP:',
      advisoryPending: 'aviso completo pendiente de publicación',
      caution: 'Atención:',
      scope: 'Ámbito:',
      downloadSuffix: '.php-2026-11-anotado.ini',
    },
    cves: {
      'CVE-2026-115560': {
        title: 'Ejecución remota de código a través del progreso de subida de sesión (session.upload_progress)',
        summary:
          'Si el servidor configura session.serialize_handler como php_binary o php_serialize y la ' +
          'aplicación lo cambia a php en tiempo de ejecución con ini_set() antes de session_start(), el ' +
          'progreso de subida de sesión escribe los datos con un manejador y la aplicación los lee con ' +
          'otro. Ese desajuste permite inyectar objetos en la sesión y puede llevar a la ejecución remota ' +
          'de código. PHP lo considera poco probable: requiere a la vez esa configuración no ' +
          'predeterminada, ese código en la aplicación y session.upload_progress activado.',
      },
    },
    version: {
      supported: 'Actualiza a PHP {target} (o superior) cuanto antes. Las mitigaciones de php.ini son temporales y parciales.',
      supportedPending:
        'La corrección se publica el 19/11/2026 (14:00-14:30 UTC), previsiblemente como PHP {target}: ' +
        'confirma el número con el anuncio oficial y actualiza en cuanto esté disponible. Hasta entonces ' +
        'aplica las mitigaciones de php.ini, que son temporales y parciales.',
      eol:
        'PHP {version} está fuera de soporte: no habrá versión oficial corregida. Depende de los parches ' +
        'que retroporte tu distribución (Debian, Ubuntu, RHEL), que mantienen el número de versión: ' +
        'comprueba el changelog del paquete, no php -v. Mantén la mitigación de forma permanente y ' +
        'planifica la migración a PHP 8.3+ (8.2 solo recibe correcciones de seguridad hasta el 31/12/2026).',
      old:
        'PHP 7.3 o anterior: sin ningún parche disponible. Aplica las mitigaciones, aísla el servicio y ' +
        'migra urgentemente a una rama con soporte (8.3 o 8.4 recomendadas).',
      unknown:
        'Versiones corregidas: 8.5.13, 8.4.28, 8.3.37 y 8.2.36. Para 8.1 y anteriores solo cabe esperar ' +
        'parches retroportados por la distribución.',
      unknownPending:
        'Las versiones corregidas se publican el 19/11/2026 (14:00-14:30 UTC) para las ramas 8.5, 8.4, ' +
        '8.3 y 8.2 (previsiblemente 8.5.13, 8.4.28, 8.3.37 y 8.2.36; confírmalo con el anuncio oficial). ' +
        'Para 8.1 y anteriores solo cabe esperar parches retroportados por la distribución.',
    },
    annotate: {
      header: [
        'php.ini anotado automáticamente - mitigaciones PHP-2026-11',
        'CVE-2026-115560 (publicación de seguridad de PHP del 19/11/2026, severidad máxima crítica)',
      ],
      generated: 'Generado el {date} - versión de PHP indicada: {version}',
      versionNotGiven: 'no indicada',
      disclaimer: [
        'Estas mitigaciones son TEMPORALES y PARCIALES. La única corrección completa es',
        'actualizar PHP a la versión publicada el 19/11/2026 y reiniciar PHP-FPM / Apache.',
        'Las líneas originales modificadas se conservan comentadas con el prefijo ";;OLD".',
        'Revisa cada cambio antes de aplicarlo en producción.',
      ],
      reason: 'Motivo:',
      caution: 'Atención:',
      actionChange: 'CAMBIO SUGERIDO',
      actionAdded: 'DIRECTIVA AÑADIDA',
      actionOptional: 'SUGERENCIA OPCIONAL (comentada)',
      actionReview: 'REVISIÓN OPCIONAL (sin cambios)',
      suggestionIfApplicable: 'Sugerencia si procede:',
      okInline: ';; PHP-2026-11: OK, valor ya seguro',
      end: ';; --- fin PHP-2026-11 ---',
      missingHeader: [
        'PHP-2026-11: directivas NO presentes en el fichero original',
        'Añadidas al final: en php.ini la última aparición de una directiva prevalece.',
      ],
      conditionalWarning: [
        'ATENCIÓN PHP-2026-11: las siguientes directivas también se redefinen dentro de secciones',
        '[PATH=...] / [HOST=...] y prevalecen para esos hosts/rutas. Revísalas manualmente:',
      ],
      conditionalLine: '{key} en las líneas {lines}',
      footer: [
        'Recordatorio final PHP-2026-11: tras aplicar los cambios reinicia TODOS los procesos',
        '(systemctl restart php-fpm / apache2) y verifica con php --ini y php -i.',
      ],
    },
    rules: {
      'session.upload_progress.enabled': {
        category: 'Mitigación recomendada por PHP',
        why:
          'Es la mitigación que PHP recomienda desde su aviso del 23/10/2026: con el progreso de subida ' +
          'de sesión desactivado, la vía de CVE-2026-115560 no se alcanza. Es la misma directiva que ya ' +
          'se recomendó para CVE-2026-109619 (PHP2Shell): si la desactivaste en octubre, mantenla así.',
        caveat:
          'Es PHP_INI_PERDIR: un .user.ini o un ini_set() de la aplicación NO deben usarse para esto. ' +
          'En PHP-FPM fíjalo también en el pool con php_admin_flag[session.upload_progress.enabled] = off ' +
          'y reinicia TODOS los procesos trabajadores. Mitigación temporal: no sustituye a la actualización.',
        details: { add: 'No está definida; el valor por defecto de PHP es On.', change: 'Está activada ({value}).' },
      },
      'session.serialize_handler': {
        category: 'Condición de exposición (revisar el código)',
        why:
          'Un manejador configurado como php_binary o php_serialize es la primera condición de ' +
          'CVE-2026-115560. La segunda está en el código: busca llamadas a ' +
          "ini_set('session.serialize_handler', 'php') anteriores a session_start(). Si se dan ambas y el " +
          'progreso de subida sigue activado, la instalación es explotable.',
        caveat:
          'No cambies el manejador sin probarlo: las sesiones ya almacenadas con otro formato dejarán de ' +
          'leerse. Lo que elimina el desajuste es que configuración y aplicación usen siempre el mismo ' +
          'manejador (y no cambiarlo en tiempo de ejecución). Revisa también conf.d/*.ini, el pool de ' +
          'PHP-FPM, .htaccess y .user.ini, donde puede redefinirse.',
        details: { info: 'Configurado como {value}: se cumple la primera condición de exposición.' },
      },
      expose_php: {
        category: 'Endurecimiento general',
        why:
          'Oculta la cabecera X-Powered-By con la versión exacta de PHP, que los escáneres masivos usan ' +
          'para localizar instalaciones sin actualizar.',
        caveat: 'No mitiga la vulnerabilidad; solo dificulta la identificación de la versión.',
        details: { add: 'No está definida (por defecto On).', change: 'Está activada ({value}).' },
      },
    },
  };
});
