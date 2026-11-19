# Analizador de `php.ini` frente a las vulnerabilidades de PHP del 19/11/2026 (CVE-2026-115560 y otras)

Aplicación web estática, pensada para desplegarse en **GitHub Pages**, que analiza un
fichero `php.ini` y genera una copia **anotada con comentarios** que explican los cambios
sugeridos para mitigar las vulnerabilidades corregidas en la publicación de seguridad de PHP
del **19/11/2026** (17 avisos, 7 de ellos **críticos**), mientras se planifica y ejecuta la
actualización de PHP.

Es la continuación del incidente de octubre
([PHP2Shell, 21/10/2026](https://github.com/ojgarciab/2026-10-21-php-vulnerable)) y reutiliza
su mismo motor.

**Todo se ejecuta en el navegador, en JavaScript puro.** El `php.ini` no se envía a ningún
servidor.

Web publicada: <https://2026-11-19-php-vulnerable.linaresdigital.com/>, disponible en
[español](https://2026-11-19-php-vulnerable.linaresdigital.com/es/) e
[inglés](https://2026-11-19-php-vulnerable.linaresdigital.com/en/).

## Propósito

### Cronología

| Fecha | Hecho |
|-------|-------|
| 21/10/2026 | PHP publica 8.5.12, 8.4.27, 8.3.36 y 8.2.35, que corrigen PHP2Shell (CVE-2026-109618 y CVE-2026-109619). |
| 23/10/2026 | Aviso informativo sobre **CVE-2026-115560**: recomienda `session.upload_progress.enabled=0` y aplaza la corrección a la siguiente publicación ordinaria. |
| 18/11/2026 | PHP anuncia publicaciones de seguridad para el día siguiente, con severidad máxima crítica. |
| 19/11/2026 | **Se publican PHP 8.5.13, 8.4.28, 8.3.37 y 8.2.36** y los 17 avisos de seguridad. |

### Versiones corregidas

**La única corrección completa es actualizar PHP** y reiniciar todos los procesos (PHP-FPM,
Apache `mod_php`, etc.). Las versiones son acumulativas: incluyen también las correcciones de
PHP2Shell de octubre.

| Rama | Versión corregida | Avisos que corrige |
|------|-------------------|--------------------|
| 8.5 | **8.5.13** | 17 |
| 8.4 | **8.4.28** | 14 |
| 8.3 | **8.3.37** | 13 |
| 8.2 | **8.2.36** | 12. Esta rama solo recibe correcciones de seguridad hasta el 31/12/2026. |
| 8.1, 8.0, 7.4 | Sin versión oficial | Ramas sin soporte. Los avisos indican que las versiones antiguas pueden estar afectadas (el progreso de subida existe desde PHP 5.4 y el fallo de PHP-FPM desde 5.6). Dependen de que la distribución (Debian, Ubuntu, RHEL, AlmaLinux…) retroporte los parches manteniendo el número de versión: compruébalo en el *changelog* del paquete, no con `php -v`. |
| 7.3 y anteriores | Sin parche | Mantener las mitigaciones, aislar y migrar. |

### Vulnerabilidades

Datos tomados de los avisos oficiales de `php-src` y de las notas (`NEWS`) de cada versión.
Todas las puntuaciones son CVSS v4. «Todas» significa las ramas 8.2 a 8.5.

#### Críticas

| CVE | Aviso | CVSS | Ramas | Descripción y condiciones |
|-----|-------|------|-------|---------------------------|
| CVE-2026-115560 | [GHSA-658j-r8rw-q6mx](https://github.com/php/php-src/security/advisories/GHSA-658j-r8rw-q6mx) | 9.2 | Todas | **Desajuste de serializadores de sesión.** El progreso de subida escribe en la sesión un valor del atacante con `php_binary` o `php_serialize`; si esa sesión se lee después con el serializador `php`, se pueden deserializar objetos y, con una cadena de *gadgets* (demostrado con Guzzle y Monolog), ejecutar código. El desajuste se da si la aplicación cambia `session.serialize_handler` antes de `session_start()` **o si distintas aplicaciones, *pools*, *virtual hosts* o tareas CLI comparten almacén de sesiones con ajustes diferentes**. |
| CVE-2026-126714 | [GHSA-fm2m-fjf5-v3cp](https://github.com/php/php-src/security/advisories/GHSA-fm2m-fjf5-v3cp) | 9.2 | Todas | **Ficheros de sesión parcialmente sobrescritos.** Una escritura interrumpida con el manejador `files` (el predeterminado) deja un fichero mezclado que al deserializarse puede ejecutar código. Requiere que el atacante influya en los datos de sesión (el progreso de subida es una vía) y una cadena de *gadgets*. |
| CVE-2026-129289 | [GHSA-qc49-hpvq-g2w6](https://github.com/php/php-src/security/advisories/GHSA-qc49-hpvq-g2w6) | 9.2 | Todas | **Contrabando de peticiones en PHP-FPM.** Si el servidor web reutiliza conexiones FastCGI (nginx `fastcgi_keep_conn on`, Apache `enablereuse=on`, HAProxy, LSAPI) y la aplicación abre `php://input` sin leerlo entero, los bytes sobrantes se interpretan como una nueva petición: permite ejecutar PHP del atacante, falsear `REMOTE_ADDR` o inyectar `PHP_ADMIN_VALUE`. No requiere corrupción de memoria. Las configuraciones estándar que cierran la conexión tras cada petición no están afectadas. |
| CVE-2026-129496 | [GHSA-gr4f-wgx5-jpfv](https://github.com/php/php-src/security/advisories/GHSA-gr4f-wgx5-jpfv) | 9.2 | Todas | **Uso tras liberación en la caché de zonas horarias.** En compilaciones sin hilos (PHP-FPM, `mod_php`), un aviso emitido en el arranque y escrito con el `error_log` de fichero de PHP deja una referencia obsoleta que la primera petición de cada trabajador puede reutilizar. |
| CVE-2026-129481 | [GHSA-g3vh-838c-65v7](https://github.com/php/php-src/security/advisories/GHSA-g3vh-838c-65v7) | 9.2 | 8.3, 8.4, 8.5 | **Uso tras liberación tras un cierre de sesión interrumpido.** Corrección incompleta de CVE-2026-109619. Requiere que la limpieza de la sesión termine en error fatal (p. ej. en el `stream_close()` de un *stream wrapper* propio) y otra petición en el mismo trabajador. |
| CVE-2026-129474 | [GHSA-8mjj-2r7p-4hg2](https://github.com/php/php-src/security/advisories/GHSA-8mjj-2r7p-4hg2) | 9.2 | 8.5 | **Uso tras liberación en los *backtraces* de métodos mágicos.** Requiere `fatal_error_backtraces=1` (por defecto en 8.5) y `zend.exception_ignore_args=0` (valor interno por defecto; `php.ini-production` lo fija a 1). |
| CVE-2026-129182 | [GHSA-2fjv-p558-g82m](https://github.com/php/php-src/security/advisories/GHSA-2fjv-p558-g82m) | 9.2 | 8.5 | **Uso tras liberación al repoblar el *backtrace* del último error fatal.** Corrección incompleta de CVE-2026-109619. PHP-FPM o `mod_php`, con ciertos avisos durante el cierre. La ejecución de código no se ha demostrado. |

#### Altas y moderadas

| CVE | Aviso | CVSS | Ramas | Descripción |
|-----|-------|------|-------|-------------|
| CVE-2026-129291 | [GHSA-jm4m-qfqx-967m](https://github.com/php/php-src/security/advisories/GHSA-jm4m-qfqx-967m) | 8.8 | Todas (8.2 desde 8.2.7) | Uso tras liberación en el *backend* `epoll` de PHP-FPM: escalada local de privilegios a root si el maestro corre como root y el *pool* tiene `catch_workers_output` activado (las imágenes Docker oficiales de PHP-FPM lo activan). |
| CVE-2026-127960 | [GHSA-mmf9-xm3v-hg2x](https://github.com/php/php-src/security/advisories/GHSA-mmf9-xm3v-hg2x) | 8.7 | Desde 8.2.28, 8.3.18, 8.4.5 y 8.5.0 | Denegación de servicio por agotamiento de CPU al analizar cabeceras HTTP plegadas en respuestas obtenidas con el *wrapper* `http(s)://`. |
| CVE-2026-128064 | [GHSA-f6gg-rchx-xw8j](https://github.com/php/php-src/security/advisories/GHSA-f6gg-rchx-xw8j) | 8.2 | Todas | Las URL con el esquema en mayúsculas (`HTTPS://`, `FTPS://`) se tratan como HTTP/FTP en claro, también en redirecciones: expone credenciales y datos. |
| CVE-2026-128090 | [GHSA-68fq-fh7h-f8gr](https://github.com/php/php-src/security/advisories/GHSA-68fq-fh7h-f8gr) | 7.7 | Todas | Elusión de la firma OpenSSL de un Phar degradando el algoritmo a un *hash* sin clave; `phar.require_hash=1` no lo impide. |
| CVE-2026-129538 | [GHSA-5j3f-64r7-f564](https://github.com/php/php-src/security/advisories/GHSA-5j3f-64r7-f564) | 6.9 | Todas | Lectura y escritura fuera de límites en `php-cgi` al corregir `PATH_INFO` con `cgi.fix_pathinfo=1`. PHP-FPM y `mod_php` no están afectados. |
| CVE-2026-129438 | [GHSA-mg3p-mxj9-g2mm](https://github.com/php/php-src/security/advisories/GHSA-mg3p-mxj9-g2mm) | 6.3 | 8.5 | Serialización incorrecta en `Uri\Rfc3986\Uri` con entradas cercanas a 2 GiB. |
| CVE-2026-129506 | [GHSA-4646-p932-gw34](https://github.com/php/php-src/security/advisories/GHSA-4646-p932-gw34) | 6.3 | Todas | Uso tras liberación en SOAP al procesar referencias a entidades de un DTD (caída del trabajador). |
| CVE-2026-15353 | [GHSA-q23r-hr55-xmpg](https://github.com/php/php-src/security/advisories/GHSA-q23r-hr55-xmpg) | 6.3 | Todas | Fuga de memoria no inicializada en SOAP con dimensiones de *array* mal formadas. |
| CVE-2026-129501 | [GHSA-x8r7-mg3g-74hg](https://github.com/php/php-src/security/advisories/GHSA-x8r7-mg3g-74hg) | 6.3 | 8.4, 8.5 | Doble liberación al serializar con `saveXml()` documentos de `Dom\XMLDocument` / `Dom\HTMLDocument` controlados por el atacante. |
| CVE-2026-129292 | [GHSA-3mg3-cr28-46gc](https://github.com/php/php-src/security/advisories/GHSA-3mg3-cr28-46gc) | 5.3 | Todas | XSS en la página de estado de PHP-FPM (`full&html`) a través del usuario de autenticación Basic o del nombre del *script*. |

PHP 8.5.13 actualiza además la biblioteca uriparser incluida a la versión 1.0.3 (CVE-2026-48841).

No se ha encontrado constancia de explotación activa de estas vulnerabilidades. Existen pruebas
de concepto públicas de CVE-2026-115560, no verificadas para este documento.

## Mitigaciones

### En `php.ini` (las que comprueba esta herramienta)

| Directiva | Valor sugerido | Severidad | CVE | Observaciones |
|-----------|----------------|-----------|-----|---------------|
| `session.upload_progress.enabled` | `Off` | Crítica | CVE-2026-115560, CVE-2026-126714 | Elimina la vía de ataque del primero y una de las vías del segundo. Debe estar desactivado en **todas** las configuraciones que escriben en el mismo almacén de sesiones. Es `PHP_INI_PERDIR`: un `ini_set()` llega tarde; en PHP-FPM, `php_admin_flag[session.upload_progress.enabled] = off`. **Las versiones corregidas lo desactivan por defecto, pero un `On` explícito lo mantiene activo**: hay que revisarlo también después de actualizar. |
| `session.serialize_handler` | Revisar (`php`) | Alta | CVE-2026-115560 | No se modifica automáticamente. Si vale `php_binary` o `php_serialize`, comprobar que todo lo que lee ese almacén de sesiones usa el mismo manejador; si no, aislar el almacén (`session.save_path`). Al cambiar de formato hay que migrar o caducar las sesiones existentes. |
| `fatal_error_backtraces` | `Off` | Crítica | CVE-2026-129182, CVE-2026-129474 | Solo PHP 8.5. Ya era mitigación de PHP2Shell. Fijarla de forma administrativa y reiniciar todos los trabajadores. |
| `zend.exception_ignore_args` | `On` | Crítica | CVE-2026-129474 | Solo explotable en PHP 8.5. `php.ini-production` ya lo trae; el valor interno por defecto es `Off`. |
| `error_log` | Revisar (`syslog`) | Alta | CVE-2026-129496 | Solo se señala si apunta a un fichero. La mitigación principal es **corregir los errores de configuración y ajustes obsoletos que generan avisos en el arranque** (p. ej. un `date.timezone` no válido); enviar los errores a `syslog` también evita la ruta vulnerable. Reiniciar maestro y trabajadores. |
| `cgi.fix_pathinfo` | `0` | Media (opcional) | CVE-2026-129538 | Solo para `php-cgi`. Puede romper el enrutado basado en `PATH_INFO`. Se añade comentada. |
| `expose_php` | `Off` | Baja | — | Endurecimiento: oculta la cabecera `X-Powered-By`. No mitiga ninguna vulnerabilidad. |

### Fuera de `php.ini` (la herramienta NO las cubre)

| Dónde | Qué hacer | CVE |
|-------|-----------|-----|
| Servidor web | **No reutilizar conexiones FastCGI**: nginx sin `fastcgi_keep_conn on`, Apache `mod_proxy_fcgi` sin `enablereuse=on`, o que el *frontend* cierre la conexión tras cada petición. No exponer los puertos de PHP-FPM / LSAPI a redes no confiables. | CVE-2026-129289 |
| *Pool* de PHP-FPM | `catch_workers_output = no` en los *pools* afectados (ojo con las imágenes Docker oficiales, que lo activan). Ejecutar el maestro sin root limita el impacto pero no corrige el fallo. | CVE-2026-129291 |
| *Pool* de PHP-FPM | `pm.max_requests = 1` impide que un trabajador contaminado atienda una segunda petición, con un coste de rendimiento alto. Desactivar el progreso de subida **no** mitiga este fallo. | CVE-2026-129481 |
| *Pool* de PHP-FPM | Desactivar la página de estado (`pm.status_path`) o no usar su salida `full&html`. | CVE-2026-129292 |
| Aplicación | Evitar errores fatales en *callbacks* de limpieza de sesión; limitar los datos no confiables guardados en sesión; usar un almacén de sesiones atómico. | CVE-2026-129481, CVE-2026-126714 |
| Aplicación | Normalizar a minúsculas el esquema de las URL antes de pasarlas a `fopen()` / `file_get_contents()`, desactivar las redirecciones automáticas o validar cada destino, y limitar las peticiones salientes a destinos de confianza. | CVE-2026-128064, CVE-2026-127960 |
| Aplicación | Proteger el fichero `<archivo>.pubkey` de los Phar firmados frente a la vía de actualización del propio archivo. | CVE-2026-128090 |
| Aplicación | Restringir los servicios SOAP, rechazar documentos con DTD y cargar WSDL solo de fuentes de confianza. | CVE-2026-129506, CVE-2026-15353 |
| Aplicación | No llamar a `saveXml()` sobre documentos DOM controlados por el atacante (`saveHtml()` no está afectado); limitar la longitud de las URI no confiables. | CVE-2026-129501, CVE-2026-129438 |

Además:

- **Actualizar PHP** y reiniciar PHP-FPM / Apache; verificar la versión en ejecución (`php -v`,
  `php --ini`, `phpinfo()`) y, en distribuciones que retroportan, el *changelog* del paquete.
- Revisar el código en busca de cambios del serializador de sesión:
  ```bash
  grep -rnE "ini_set\(\s*['\"]session\.serialize_handler" /ruta/de/la/aplicacion
  ```
- Revisar el resto de fuentes de configuración: `conf.d/*.ini`, *pools* de PHP-FPM, `.user.ini`,
  `.htaccess` (`php_value`). La herramienta solo analiza el fichero que se le entrega.

## Qué hace la web

Igual que la de octubre:

1. Permite **arrastrar, seleccionar o pegar** un `php.ini` (o cargar un ejemplo).
2. Opcionalmente, indicar la **versión de PHP** para adaptar las recomendaciones (varias
   directivas solo aplican a 8.5) y mostrar la versión objetivo.
3. Analiza las directivas respetando la semántica de `php.ini` (última aparición prevalece,
   comillas, booleanos, secciones `[PATH=…]` / `[HOST=…]` detectadas pero no modificadas).
4. Muestra una **tabla de hallazgos** (OK / Cambiar / Añadir / Revisar / No aplica).
5. Genera y permite **descargar un `php.ini` anotado**: conserva el original, antepone a cada
   cambio un bloque `;;` con el CVE, el motivo y las precauciones, y deja la línea original
   comentada con el prefijo `;;OLD`.

## Despliegue en GitHub Pages

El sitio es completamente estático y vive en la carpeta `docs/`. Hay una página HTML por idioma
(`docs/es/` y `docs/en/`; faltan fr, it, de y pt respecto a octubre), generadas desde una plantilla única por
`tools/build-pages.py`, que comparten la hoja de estilos y el JavaScript de `docs/css` y
`docs/js`. La raíz `docs/index.html` redirige al idioma guardado en el navegador o, si no lo hay,
al del propio navegador (español por defecto).

GitHub Pages se configura en *Settings → Pages* con *Deploy from a branch*, rama `master` y carpeta
`/docs`, de modo que cada *push* a `master` actualiza la web. El dominio propio se declara en
`docs/CNAME`, y `docs/.nojekyll` evita el procesado de Jekyll. Las pruebas se ejecutan en cada
*push* mediante `.github/workflows/test.yml`.

Para probar en local:

```bash
python3 -m http.server 8080 --directory docs   # o: npm start
```

## Estructura y pruebas

```
docs/index.html            Redirección al idioma del usuario
docs/<idioma>/index.html   Interfaz en cada idioma (es, en), generada por tools/build-pages.py
docs/css/style.css         Estilos comunes (modo claro/oscuro, adaptable a móvil)
docs/js/analyzer.js        Parser de php.ini, reglas y generador del fichero anotado (sin dependencias)
docs/js/locale-<idioma>.js Textos de cada idioma (interfaz, explicaciones y comentarios del fichero generado)
docs/js/app.js             Lógica de la interfaz común (carga, tabla de resultados, descarga)
docs/js/sample.js          Extracto de php.ini-production para pruebas
tools/build-pages.py       Plantilla HTML y textos estáticos de cada idioma
test/analyzer.test.js      Pruebas con el módulo `node:assert`
```

```bash
node test/analyzer.test.js   # o: npm test
```

Para añadir una comprobación basta con editar la lista `RULES` de `docs/js/analyzer.js` y añadir
sus textos en cada `docs/js/locale-*.js` (las pruebas comprueban que todos los idiomas tienen las
mismas claves). Para añadir un idioma: copiar `docs/js/locale-es.js` con el nuevo código, añadir
su entrada en `LANGS` de `tools/build-pages.py`, ejecutar el script, y añadir el código a la lista
`supported` de `docs/index.html` y a `LOCALES` de las pruebas.

## Fuentes

- PHP, [avisos de seguridad de `php-src`](https://github.com/php/php-src/security/advisories) publicados el 19/11/2026 (enlazados uno a uno en las tablas anteriores).
- PHP, notas de las versiones: `NEWS` de las etiquetas [php-8.5.13](https://github.com/php/php-src/blob/php-8.5.13/NEWS), [php-8.4.28](https://github.com/php/php-src/blob/php-8.4.28/NEWS), [php-8.3.37](https://github.com/php/php-src/blob/php-8.3.37/NEWS) y [php-8.2.36](https://github.com/php/php-src/blob/php-8.2.36/NEWS).
- LWN, [Four PHP security releases including fixes for critical vulnerabilities](https://lwn.net/Articles/1108552/).
- The Hacker News, [PHP Warns of Critical Security Flaws Affecting All Supported Versions, Fixes Coming November 19](https://thehackernews.com/2026/11/php-warns-of-critical-security-flaws.html).
- The Register, [Get ready for another critical PHP security release to drop](https://www.theregister.com/patches/2026/11/18/get-ready-for-another-critical-php-security-release-to-drop/5310911) (18/11/2026).
- Aikido, [PHP schedules a critical security release for 19 November, including CVE-2026-115560](https://www.aikido.dev/blog/php-security-release-19-november-2026-cve-2026-115560).
- Incidente anterior: [ojgarciab/2026-10-21-php-vulnerable](https://github.com/ojgarciab/2026-10-21-php-vulnerable).

El anuncio de php.net, el artículo de The Hacker News y la web de INCIBE-CERT no eran accesibles
desde el entorno en el que se preparó este documento; no se ha comprobado si INCIBE-CERT ha
publicado un aviso propio.

## Licencia

GPL-3.0. Véase [LICENSE](LICENSE).

> Herramienta de apoyo sin garantías. Las mitigaciones de `php.ini` son parciales y temporales;
> la única corrección completa es actualizar PHP.
