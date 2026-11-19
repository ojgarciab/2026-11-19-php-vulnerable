# Analizador de `php.ini` frente a CVE-2026-115560 (publicación de seguridad de PHP del 19/11/2026)

Aplicación web estática, pensada para desplegarse en **GitHub Pages**, que analiza un
fichero `php.ini` y genera una copia **anotada con comentarios** que explican los cambios
sugeridos para mitigar las vulnerabilidades que corrige la publicación de seguridad de PHP
del **19/11/2026** (severidad máxima **crítica**), mientras se planifica y ejecuta la
actualización de PHP.

Es la continuación del incidente de octubre
([PHP2Shell, 21/10/2026](https://github.com/ojgarciab/2026-10-21-php-vulnerable)) y reutiliza
su mismo motor.

**Todo se ejecuta en el navegador, en JavaScript puro.** El `php.ini` no se envía a ningún
servidor.

Web publicada: <https://2026-11-19-php-vulnerable.linaresdigital.com/>, disponible en
[español](https://2026-11-19-php-vulnerable.linaresdigital.com/es/) e
[inglés](https://2026-11-19-php-vulnerable.linaresdigital.com/en/).

> [!WARNING]
> **Estado: esqueleto, redactado el 19/11/2026 a las 08:15 UTC, antes de la publicación.**
> PHP publica las versiones corregidas hoy entre las **14:00 y las 14:30 UTC**. Hasta entonces
> no se conocen la lista completa de CVE, los identificadores GHSA, las puntuaciones CVSS ni los
> números de versión definitivos. Todo lo marcado como **PENDIENTE** en este documento y en el
> código debe confirmarse con los avisos oficiales (véase [Qué actualizar tras la publicación](#qué-actualizar-tras-la-publicación)).
>
> Las fuentes originales (php.net, The Hacker News, The Register…) no eran accesibles desde el
> entorno en el que se preparó este documento: la información procede de resultados de búsqueda
> que las resumen y citan, no de su lectura directa.

## Propósito

### Cronología

| Fecha | Hecho |
|-------|-------|
| 21/10/2026 | PHP publica 8.5.12, 8.4.27, 8.3.36 y 8.2.35, que corrigen PHP2Shell (CVE-2026-109618 y CVE-2026-109619). |
| 23/10/2026 | PHP publica un aviso informativo sobre **CVE-2026-115560**: una vía «poco probable» de ejecución remota de código en el progreso de subida de sesión. Recomienda `session.upload_progress.enabled=0` y aplaza la corrección a la siguiente publicación ordinaria. |
| 26/10/2026 | Nuevas compilaciones para Windows (8.5.12-1, 8.4.27-1, 8.3.36-1, 8.2.35-1) que corrigen CVE-2026-111497 en la biblioteca Brotli incluida. |
| 18/11/2026 | El equipo de seguridad de PHP anuncia en php.net publicaciones de seguridad para el día siguiente, dentro del ciclo ordinario de cuatro semanas: afectan a **todas las ramas con soporte** y «la severidad más alta es CRÍTICA». |
| 19/11/2026, 14:00-14:30 UTC | **Publicación de las versiones corregidas** y de los avisos completos. |

### Vulnerabilidades

| CVE | Aviso de PHP | Descripción | CVSS |
|-----|--------------|-------------|------|
| CVE-2026-115560 | PENDIENTE (el aviso completo se publica con las versiones) | Ejecución remota de código a través del progreso de subida de sesión (`session.upload_progress`). El progreso de subida escribe los datos de sesión con el manejador configurado y la aplicación los lee con otro distinto; ese desajuste permite inyectar objetos en la sesión. | PENDIENTE (sin puntuación publicada) |
| Otras | PENDIENTE | El anuncio habla de «vulnerabilidades» en plural, pero solo se ha nombrado CVE-2026-115560. | PENDIENTE |

Según PHP, las vulnerabilidades calificadas como críticas **requieren una configuración no
predeterminada o instalaciones poco habituales**. En el caso de CVE-2026-115560 deben cumplirse
**las tres condiciones a la vez**:

1. La configuración del servidor fija `session.serialize_handler` a `php_binary` o `php_serialize`
   (el valor por defecto es `php`).
2. El código de la aplicación lo cambia a `php` en tiempo de ejecución con
   `ini_set('session.serialize_handler', 'php')` **antes** de `session_start()`.
3. `session.upload_progress.enabled` sigue activado (es el valor por defecto).

WordPress y Joomla en su configuración estándar no cumplen estas condiciones. Aun así:

- Existen **pruebas de concepto públicas** (una de ellas dice estar validada sobre la imagen
  `php:8.4.27-apache`, es decir, sobre una versión ya parcheada contra PHP2Shell). No se han
  verificado para este documento.
- No se ha encontrado constancia de explotación activa de CVE-2026-115560. Las dos
  vulnerabilidades de octubre sí están en el catálogo KEV de CISA.
- A fecha de redacción no se ha localizado un aviso específico de INCIBE-CERT para esta
  publicación (PENDIENTE de comprobar).

### Versiones corregidas

**La única corrección completa es actualizar PHP** y reiniciar todos los procesos (PHP-FPM,
Apache `mod_php`, etc.). Las publicaciones son acumulativas: incluyen también las correcciones
de PHP2Shell de octubre.

| Rama | Versión vulnerable más reciente | Versión corregida |
|------|--------------------------------|-------------------|
| 8.5 | 8.5.12 | **PENDIENTE** – se publica el 19/11/2026 (previsiblemente 8.5.13) |
| 8.4 | 8.4.27 | **PENDIENTE** – se publica el 19/11/2026 (previsiblemente 8.4.28) |
| 8.3 | 8.3.36 | **PENDIENTE** – se publica el 19/11/2026 (previsiblemente 8.3.37) |
| 8.2 | 8.2.35 | **PENDIENTE** – se publica el 19/11/2026 (previsiblemente 8.2.36). Esta rama solo recibe correcciones de seguridad hasta el 31/12/2026. |
| 8.1, 8.0, 7.4 | — | Sin versión oficial: ramas sin soporte. Dependen de que la distribución (Debian, Ubuntu, RHEL, AlmaLinux…) retroporte el parche manteniendo el número de versión: compruébalo en el *changelog* del paquete, no con `php -v`. A 11/11/2026 no constaban entradas para este CVE en los rastreadores de Debian ni Ubuntu. |
| 7.3 y anteriores | — | Sin parche. Mantener la mitigación, aislar y migrar. |

Los números «previsibles» son el siguiente parche de cada rama; **no están confirmados** por PHP.

## Mitigaciones

| Directiva | Valor sugerido | Severidad | CVE | Observaciones |
|-----------|----------------|-----------|-----|---------------|
| `session.upload_progress.enabled` | `Off` | Crítica (provisional) | CVE-2026-115560 | **Mitigación recomendada por PHP** desde el 23/10/2026. Es la misma que se recomendó para CVE-2026-109619: quien la aplicó en octubre ya está cubierto y debe mantenerla. Es `PHP_INI_PERDIR`: no sirve `ini_set()`, y no conviene confiar en `.user.ini`. En PHP-FPM fijarla además en el *pool* con `php_admin_flag[session.upload_progress.enabled] = off` y reiniciar todos los trabajadores. |
| `session.serialize_handler` | Revisar (`php`) | Alta | CVE-2026-115560 | No se modifica automáticamente. Si vale `php_binary` o `php_serialize` se cumple la primera condición de exposición: hay que buscar en el código llamadas a `ini_set('session.serialize_handler', 'php')` previas a `session_start()`. Lo que elimina el desajuste es que configuración y aplicación usen siempre el mismo manejador; cambiarlo sin pruebas invalida las sesiones almacenadas. |
| `expose_php` | `Off` | Baja | — | Endurecimiento: oculta la cabecera `X-Powered-By`. No mitiga la vulnerabilidad. |

La severidad «crítica» de la primera fila es provisional: PHP ha dicho que la severidad máxima de
la publicación es crítica, pero no ha confirmado todavía la puntuación de CVE-2026-115560.

### Lo que la web NO puede cubrir (y conviene hacer igualmente)

- **Actualizar PHP** en cuanto se publiquen las versiones y reiniciar PHP-FPM / Apache; verificar
  la versión en ejecución (`php -v`, `php --ini`, `phpinfo()`) y, en distribuciones que
  retroportan, el *changelog* del paquete.
- **Revisar el código de la aplicación**, que es donde está la segunda condición:
  ```bash
  grep -rnE "ini_set\(\s*['\"]session\.serialize_handler" /ruta/de/la/aplicacion
  ```
- Fuentes de configuración adicionales: `conf.d/*.ini`, *pool* de PHP-FPM, `.user.ini`,
  `.htaccess` (`php_value`). La herramienta solo analiza el fichero que se le entrega.
- Mantener las mitigaciones y la actualización de octubre si aún no se aplicaron: las versiones
  anteriores a 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 siguen siendo vulnerables a PHP2Shell, que sí
  se está explotando.

## Qué hace la web

Igual que la de octubre:

1. Permite **arrastrar, seleccionar o pegar** un `php.ini` (o cargar un ejemplo).
2. Opcionalmente, indicar la **versión de PHP** para mostrar la versión objetivo.
3. Analiza las directivas respetando la semántica de `php.ini` (última aparición prevalece,
   comillas, booleanos, secciones `[PATH=…]` / `[HOST=…]` detectadas pero no modificadas).
4. Muestra una **tabla de hallazgos** (OK / Cambiar / Añadir / Revisar / No aplica).
5. Genera y permite **descargar un `php.ini` anotado**: conserva el original, antepone a cada
   cambio un bloque `;;` con el CVE, el motivo y las precauciones, y deja la línea original
   comentada con el prefijo `;;OLD`.

## Qué actualizar tras la publicación

Los puntos pendientes están marcados con `PENDIENTE` en el código (`grep -rn PENDIENTE .`):

1. `docs/js/analyzer.js`: confirmar `FIXED_VERSIONS`, poner `RELEASE_CONFIRMED = true`, añadir el
   GHSA de CVE-2026-115560 y los demás CVE a `CVES`, y las reglas nuevas a `RULES`.
2. `tools/build-pages.py`: confirmar `FIXED`, cambiar «corrección prevista en» por «corregida en»
   y ejecutar `npm run build`.
3. `docs/js/locale-*.js`: textos de los CVE y reglas nuevos, y versiones en `version.unknown`.
4. Este README: tablas de vulnerabilidades, versiones y fuentes; retirar el aviso de estado.
5. Añadir los idiomas restantes (fr, it, de, pt), que el esqueleto no incluye todavía.

## Despliegue en GitHub Pages

El sitio es completamente estático y vive en la carpeta `docs/`. Hay una página HTML por idioma
(`docs/es/` y `docs/en/` por ahora), generadas desde una plantilla única por
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

- PHP, aviso de seguridad del 18/11/2026 y aviso informativo del 23/10/2026 sobre CVE-2026-115560, en [php.net](https://www.php.net/). Los avisos completos se publicarán en [php-src/security/advisories](https://github.com/php/php-src/security/advisories).
- The Hacker News, [PHP Warns of Critical Security Flaws Affecting All Supported Versions, Fixes Coming November 19](https://thehackernews.com/2026/11/php-warns-of-critical-security-flaws.html).
- The Register, [Get ready for another critical PHP security release to drop](https://www.theregister.com/patches/2026/11/18/get-ready-for-another-critical-php-security-release-to-drop/5310911) (18/11/2026).
- SecurityWeek, [PHP Readies Critical Security Updates to Patch Another RCE Flaw](https://www.securityweek.com/php-readies-critical-security-updates-to-patch-another-rce-flaw/).
- Aikido, [PHP schedules a critical security release for 19 November, including CVE-2026-115560](https://www.aikido.dev/blog/php-security-release-19-november-2026-cve-2026-115560).
- IT-Connect, [PHP Security Update: Critical Flaw Fixes Coming for 8.2-8.5](https://www.it-connect.tech/php-to-patch-at-least-one-critical-flaw-this-thursday-update-php-8-2-to-8-5/).
- Brandefense, [CVE-2026-115560: PHP Session RCE Flaw, Patch and PoC Status](https://brandefense.io/knowledge-hub/vulnerabilities/cve-2026-115560/).
- mySites.guru, [Turn Off PHP Session Upload Progress](https://mysites.guru/blog/php-session-upload-progress-advisory/).
- F5, [K000163878: PHP vulnerability CVE-2026-115560](https://my.f5.com/manage/s/article/K000163878).
- Incidente anterior: [ojgarciab/2026-10-21-php-vulnerable](https://github.com/ojgarciab/2026-10-21-php-vulnerable).

## Licencia

GPL-3.0. Véase [LICENSE](LICENSE).

> Herramienta de apoyo sin garantías. Las mitigaciones de `php.ini` son parciales y temporales;
> la única corrección completa es actualizar PHP.
