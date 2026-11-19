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
      caution: 'Atención:',
      scope: 'Ámbito:',
      downloadSuffix: '.php-2026-11-anotado.ini',
    },
    cves: {
      "CVE-2026-115560": {
        "title": "Desajuste de serializadores de sesión que puede llevar a ejecución remota de código",
        "summary": "El progreso de subida de sesión escribe en la sesión un valor controlado por el atacante con el serializador configurado (php_binary o php_serialize). Si después esa misma sesión se lee con el serializador php, los delimitadores inyectados permiten deserializar objetos y, con una cadena de gadgets adecuada, ejecutar código. El desajuste se da si la aplicación cambia session.serialize_handler antes de session_start() o si distintas aplicaciones, pools, virtual hosts o tareas CLI comparten almacén de sesiones con ajustes diferentes. Afecta a 8.2-8.5. La corrección desactiva el progreso de subida por defecto, pero un valor explícito lo sigue activando."
      },
      "CVE-2026-126714": {
        "title": "Ficheros de sesión parcialmente sobrescritos que pueden llevar a ejecución remota de código",
        "summary": "Una escritura de sesión interrumpida con el manejador files (el predeterminado) deja un fichero mezclado que, al deserializarse, puede ejecutar código si la aplicación tiene una cadena de gadgets. Requiere que el atacante influya en los datos de sesión (el progreso de subida es una de las vías). Afecta a 8.2-8.5. Desactivar el progreso de subida solo cierra esa vía."
      },
      "CVE-2026-129289": {
        "title": "Contrabando de peticiones en PHP-FPM a través de un cuerpo de petición sin leer",
        "summary": "Si el servidor web reutiliza las conexiones FastCGI (nginx fastcgi_keep_conn on, Apache mod_proxy_fcgi enablereuse=on, HAProxy, LSAPI) y la aplicación abre php://input sin leerlo entero, los bytes sobrantes se interpretan como una nueva petición FastCGI: permite ejecutar PHP del atacante como el trabajador. No necesita corrupción de memoria. Afecta a 8.2-8.5. NO se mitiga desde php.ini: desactiva la reutilización de conexiones en el servidor web y no expongas el puerto de PHP-FPM."
      },
      "CVE-2026-129496": {
        "title": "Uso tras liberación en la caché de zonas horarias que puede llevar a ejecución remota de código",
        "summary": "En compilaciones sin hilos (PHP-FPM, mod_php), un aviso emitido durante el arranque y escrito con el error_log de fichero de PHP deja una referencia obsoleta que la primera petición de cada trabajador puede reutilizar. Afecta a 8.2-8.5. Mitigación: corregir los errores y ajustes obsoletos de configuración que generan avisos en el arranque, o enviar los errores a syslog, y reiniciar el maestro y todos los trabajadores."
      },
      "CVE-2026-129481": {
        "title": "Uso tras liberación tras un cierre de sesión interrumpido",
        "summary": "Si la limpieza de la sesión termina en error fatal (por ejemplo en el stream_close() de un stream wrapper propio), la siguiente petición atendida por el mismo trabajador reutiliza memoria liberada. Es una corrección incompleta de CVE-2026-109619. Afecta a 8.3-8.5 (8.2 no). NO se mitiga desde php.ini ni desactivando el progreso de subida; en PHP-FPM, pm.max_requests = 1 lo evita con un coste de rendimiento alto."
      },
      "CVE-2026-129474": {
        "title": "Uso tras liberación en los backtraces de métodos mágicos (solo PHP 8.5)",
        "summary": "Con fatal_error_backtraces activado y zend.exception_ignore_args desactivado, un error fatal por memory_limit durante una llamada a __call()/__callStatic() deja memoria liberada accesible. Solo PHP 8.5. php.ini-production ya fija zend.exception_ignore_args = On, que lo evita; el valor interno por defecto es Off."
      },
      "CVE-2026-129182": {
        "title": "Uso tras liberación al repoblar el backtrace del último error fatal tras el cierre (solo PHP 8.5)",
        "summary": "Corrección incompleta de CVE-2026-109619: ciertos avisos emitidos durante el cierre vuelven a rellenar el backtrace del error fatal y una petición posterior del mismo trabajador lo reutiliza. Solo PHP 8.5 con PHP-FPM o mod_php. Mitigación: fatal_error_backtraces = Off y reiniciar todos los trabajadores."
      },
      "CVE-2026-129538": {
        "title": "Lectura y escritura fuera de límites en PHP-CGI al corregir PATH_INFO",
        "summary": "Afecta solo al binario php-cgi (modos CGI y FastCGI), no a PHP-FPM ni a mod_php, con cgi.fix_pathinfo = 1 (valor por defecto) y determinados mapeos del servidor web. Provoca caídas y fuga de memoria; la ejecución de código no está confirmada. Afecta a 8.2-8.5."
      }
    },
    version: {
      "supported": "Actualiza a PHP {target} (o superior) cuanto antes y reinicia todos los procesos. Las mitigaciones de php.ini son temporales y parciales: varias vulnerabilidades críticas de esta publicación no se pueden mitigar desde php.ini.",
      "supportedPending": "Actualiza a PHP {target} en cuanto esté disponible.",
      "eol": "PHP {version} está fuera de soporte: no hay versión oficial corregida y los avisos indican que las versiones antiguas pueden estar afectadas. Depende de los parches que retroporte tu distribución (Debian, Ubuntu, RHEL), que mantienen el número de versión: comprueba el changelog del paquete, no php -v. Mantén las mitigaciones y planifica la migración a PHP 8.3+ (8.2 solo recibe correcciones de seguridad hasta el 31/12/2026).",
      "old": "PHP 7.3 o anterior: sin ningún parche disponible. Aplica las mitigaciones, aísla el servicio y migra urgentemente a una rama con soporte (8.3 o 8.4 recomendadas).",
      "unknown": "Versiones corregidas (19/11/2026): 8.5.13, 8.4.28, 8.3.37 y 8.2.36. Para 8.1 y anteriores solo cabe esperar parches retroportados por la distribución.",
      "unknownPending": "Versiones corregidas pendientes de publicación."
    },
    annotate: {
      header: [
        "php.ini anotado automáticamente - mitigaciones PHP-2026-11",
        "Publicación de seguridad de PHP del 19/11/2026 (17 avisos, 7 críticos, CVSS máx. 9.2)"
      ],
      generated: 'Generado el {date} - versión de PHP indicada: {version}',
      versionNotGiven: 'no indicada',
      disclaimer: [
        "Estas mitigaciones son TEMPORALES y PARCIALES. La única corrección completa es",
        "actualizar PHP (8.5.13 / 8.4.28 / 8.3.37 / 8.2.36) y reiniciar PHP-FPM / Apache.",
        "CVE-2026-129289 (PHP-FPM) y CVE-2026-129481 NO se mitigan desde php.ini.",
        "Las líneas originales modificadas se conservan comentadas con el prefijo \";;OLD\".",
        "Revisa cada cambio antes de aplicarlo en producción."
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
      "session.upload_progress.enabled": {
        "category": "Mitigación recomendada por PHP",
        "why": "Con el progreso de subida de sesión desactivado se elimina la vía de ataque de CVE-2026-115560 y una de las vías de CVE-2026-126714. Las versiones corregidas lo desactivan por defecto, pero un valor explícito a On lo vuelve a activar: revísalo también DESPUÉS de actualizar.",
        "caveat": "Debe estar desactivado en TODAS las configuraciones que escriben en el mismo almacén de sesiones (php.ini, pools de PHP-FPM, virtual hosts, tareas CLI). Es PHP_INI_PERDIR: un ini_set() de la aplicación llega tarde. En PHP-FPM fíjalo con php_admin_flag[session.upload_progress.enabled] = off y reinicia todos los trabajadores. No protege a las aplicaciones que guardan en sesión datos controlados por el atacante (CVE-2026-126714) ni mitiga CVE-2026-129481.",
        "details": {
          "add": "No está definida; en las versiones sin corregir el valor por defecto es On.",
          "change": "Está activada explícitamente ({value}); así sigue activa incluso tras actualizar."
        }
      },
      "session.serialize_handler": {
        "category": "Condición de exposición (revisar)",
        "why": "CVE-2026-115560 necesita que una sesión escrita con php_binary o php_serialize se lea con el serializador php. Ocurre si la aplicación cambia el manejador antes de session_start(), pero también si otra aplicación, pool, virtual host o tarea CLI con un ajuste distinto comparte el mismo almacén de sesiones (los pools de PHP-FPM no separan el almacén por sí solos).",
        "caveat": "No cambies el manejador sin probarlo: al cambiar el formato de un almacén hay que migrar o caducar las sesiones existentes, no leerlas con el serializador nuevo. Si las aplicaciones necesitan formatos distintos, aísla su almacén de sesiones (session.save_path). Tras actualizar, PHP rechaza los cambios de ajustes de sesión en tiempo de ejecución mientras el progreso de subida esté activado.",
        "details": {
          "info": "Configurado como {value}: comprueba que todo lo que lee este almacén de sesiones usa el mismo manejador."
        }
      },
      "fatal_error_backtraces": {
        "category": "Mitigación recomendada por PHP (solo PHP 8.5)",
        "why": "Desactivar los backtraces de error fatal cierra CVE-2026-129182 y CVE-2026-129474, dos usos tras liberación críticos que solo afectan a PHP 8.5. Ya era una mitigación de PHP2Shell: si lo desactivaste en octubre, mantenlo así.",
        "caveat": "La directiva solo existe en PHP 8.5. Fíjala de forma administrativa (php.ini o php_admin_flag en el pool) para que ninguna configuración por petición pueda reactivarla, y reinicia todos los trabajadores. Cambiar solo la configuración de CLI no basta.",
        "details": {
          "skip": "Solo aplica a PHP 8.5.",
          "add": "No está definida; el valor por defecto en 8.5 es On.",
          "info": "Solo aplica si usas PHP 8.5. Se añade comentada como referencia.",
          "change": "Está activada ({value})."
        }
      },
      "zend.exception_ignore_args": {
        "category": "Mitigación recomendada por PHP (solo PHP 8.5)",
        "why": "Con los argumentos excluidos de los backtraces no se alcanza la ruta de CVE-2026-129474. php.ini-production ya lo fija a On, pero el valor interno por defecto es Off, así que una instalación sin esta línea queda expuesta.",
        "caveat": "Los backtraces de excepciones dejarán de incluir los argumentos de las funciones (lo recomendado en producción). Comprueba la configuración efectiva de los trabajadores, incluidos los pools de PHP-FPM y los ajustes de la aplicación. display_errors = Off no evita la vulnerabilidad.",
        "details": {
          "skip": "Solo es explotable en PHP 8.5.",
          "add": "No está definida; el valor interno por defecto es Off.",
          "info": "Solo es explotable en PHP 8.5. Se añade comentada como referencia.",
          "change": "Está desactivada ({value})."
        }
      },
      "error_log": {
        "category": "Condición de exposición (revisar)",
        "why": "CVE-2026-129496 necesita que un aviso emitido durante el arranque se escriba con el error_log de fichero de PHP. Enviar los errores a syslog evita esa ruta; el registro de errores propio de PHP-FPM tampoco la alcanza.",
        "caveat": "La mitigación principal es corregir los errores de configuración y los ajustes obsoletos que generan avisos en el arranque (por ejemplo un date.timezone no válido): revisa el log tras reiniciar. Si cambias a syslog, comprueba que tu recogida de logs lo contempla. Reinicia el maestro y todos los trabajadores.",
        "details": {
          "info": "Los errores se escriben en un fichero ({value})."
        }
      },
      "cgi.fix_pathinfo": {
        "category": "Reducción de superficie (solo php-cgi, opcional)",
        "why": "Con cgi.fix_pathinfo = 0 no se ejecuta la corrección de PATH_INFO vulnerable de CVE-2026-129538. Solo afecta al binario php-cgi (CGI y FastCGI); PHP-FPM y mod_php no son vulnerables a este fallo.",
        "caveat": "OPCIONAL: puede romper el enrutado de aplicaciones que dependen de PATH_INFO; pruébalo antes. Si no usas php-cgi no lo necesitas. Restringe además el acceso directo a los puertos FastCGI.",
        "details": {
          "infoAbsent": "No está definida (por defecto 1). Se añade comentada para que decidas.",
          "infoOn": "Está activada. Se añade una sugerencia comentada para que decidas."
        }
      },
      "expose_php": {
        "category": "Endurecimiento general",
        "why": "Oculta la cabecera X-Powered-By con la versión exacta de PHP, que los escáneres masivos usan para localizar instalaciones sin actualizar.",
        "caveat": "No mitiga ninguna vulnerabilidad; solo dificulta la identificación de la versión.",
        "details": {
          "add": "No está definida (por defecto On).",
          "change": "Está activada ({value})."
        }
      }
    },
  };
});
