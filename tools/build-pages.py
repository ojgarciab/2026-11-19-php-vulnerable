#!/usr/bin/env python3
"""Genera docs/<idioma>/index.html para cada idioma a partir de una plantilla única.

Uso: python3 tools/build-pages.py
Los textos de la interfaz que genera JavaScript viven en docs/js/locale-<idioma>.js.
"""
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent / "docs"

LANGS = {
    "es": {
        "name": "Español",
        "title": "Analizador php.ini · PHP 19/11/2026",
        "description": "Analiza un php.ini en tu navegador y descarga una versión anotada con las mitigaciones de las vulnerabilidades críticas corregidas en PHP 8.5.13, 8.4.28, 8.3.37 y 8.2.36 (19/11/2026) mientras actualizas PHP.",
        "nav_label": "Idioma",
        "eyebrow": "PHP · publicación de seguridad del 19/11/2026 · severidad máxima crítica",
        "h1": "Analizador de <code>php.ini</code> frente a las vulnerabilidades de PHP del 19/11/2026",
        "lead": "Sube tu <code>php.ini</code> y obtén una copia anotada con los cambios sugeridos para mitigar las vulnerabilidades críticas corregidas en <strong>PHP 8.5.13, 8.4.28, 8.3.37 y 8.2.36</strong> (entre ellas CVE-2026-115560) mientras actualizas PHP. Todo se procesa en tu navegador: el fichero nunca sale de tu equipo.",
        "step1": "1. Carga el fichero",
        "drop": "<strong>Arrastra aquí tu php.ini</strong> o pulsa para seleccionarlo",
        "nofile": "Ningún fichero seleccionado",
        "sample": "Cargar ejemplo (php.ini-production)",
        "clear": "Limpiar",
        "version_label": "Versión de PHP en el servidor",
        "v_unknown": "No lo sé / no indicar",
        "v_fixed": "{v} (corregida en {fix})",
        "v_eol": "{v} (sin soporte: solo parches de distribución)",
        "v_old": "7.3 o anterior (sin parche)",
        "version_help": "Puedes obtenerla con <code>php -v</code>. Sirve para adaptar las recomendaciones (varias directivas solo aplican a 8.5).",
        "paste_label": "O pega el contenido directamente",
        "placeholder": "; contenido de php.ini",
        "analyze": "Analizar",
        "step2": "2. Resultado del análisis",
        "th": ["Estado", "Directiva", "Línea", "Valor actual", "Sugerido", "CVE", "Severidad"],
        "download": "Descargar php.ini anotado",
        "copy": "Copiar al portapapeles",
        "preview": "Ver / ocultar vista previa",
        "about": "¿Qué comprueba esta herramienta?",
        "sources": "Fuentes: avisos de seguridad de PHP publicados el 19/11/2026 (php-src) y notas de las versiones 8.5.13, 8.4.28, 8.3.37 y 8.2.36. Consulta el <a href=\"https://github.com/ojgarciab/2026-11-19-php-vulnerable#readme\">README</a> del proyecto.",
        "footer": "Herramienta de apoyo, sin garantías. Las mitigaciones de <code>php.ini</code> son parciales: la única corrección completa es actualizar PHP y reiniciar todos los procesos.",
    },
    "en": {
        "name": "English",
        "title": "php.ini Analyzer · PHP 2026-11-19",
        "description": "Analyze a php.ini in your browser and download an annotated version with the mitigations for the critical vulnerabilities fixed in PHP 8.5.13, 8.4.28, 8.3.37 and 8.2.36 (2026-11-19) while you upgrade PHP.",
        "nav_label": "Language",
        "eyebrow": "PHP · security release of 2026-11-19 · highest severity critical",
        "h1": "<code>php.ini</code> analyzer against the PHP vulnerabilities of 2026-11-19",
        "lead": "Upload your <code>php.ini</code> and get an annotated copy with the suggested changes to mitigate the critical vulnerabilities fixed in <strong>PHP 8.5.13, 8.4.28, 8.3.37 and 8.2.36</strong> (CVE-2026-115560 among them) while you upgrade PHP. Everything runs in your browser: the file never leaves your computer.",
        "step1": "1. Load the file",
        "drop": "<strong>Drop your php.ini here</strong> or click to choose it",
        "nofile": "No file selected",
        "sample": "Load sample (php.ini-production)",
        "clear": "Clear",
        "version_label": "PHP version on the server",
        "v_unknown": "Unknown / don't specify",
        "v_fixed": "{v} (fixed in {fix})",
        "v_eol": "{v} (end-of-life: distribution patches only)",
        "v_old": "7.3 or earlier (no patch)",
        "version_help": "You can get it with <code>php -v</code>. It tailors the recommendations (several directives only apply to 8.5).",
        "paste_label": "Or paste the contents directly",
        "placeholder": "; php.ini contents",
        "analyze": "Analyze",
        "step2": "2. Analysis results",
        "th": ["Status", "Directive", "Line", "Current value", "Suggested", "CVE", "Severity"],
        "download": "Download annotated php.ini",
        "copy": "Copy to clipboard",
        "preview": "Show / hide preview",
        "about": "What does this tool check?",
        "sources": "Sources: PHP security advisories published on 2026-11-19 (php-src) and the release notes of 8.5.13, 8.4.28, 8.3.37 and 8.2.36. See the project <a href=\"https://github.com/ojgarciab/2026-11-19-php-vulnerable#readme\">README</a>.",
        "footer": "Support tool, provided without warranty. <code>php.ini</code> mitigations are partial: the only complete fix is to upgrade PHP and restart every process.",
    },
}

# Mantener sincronizado con FIXED_VERSIONS de docs/js/analyzer.js.
FIXED = [("8.5", "8.5.13"), ("8.4", "8.4.28"), ("8.3", "8.3.37"), ("8.2", "8.2.36")]
EOL = ["8.1", "8.0", "7.4"]
FAVICON = "data:image/svg+xml,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 32 32%22%3E%3Crect width=%2232%22 height=%2232%22 rx=%226%22 fill=%22%234f46e5%22/%3E%3Ctext x=%2216%22 y=%2222%22 font-size=%2216%22 text-anchor=%22middle%22 fill=%22white%22 font-family=%22sans-serif%22 font-weight=%22bold%22%3Eini%3C/text%3E%3C/svg%3E"

TEMPLATE = """<!doctype html>
<!-- Generado por tools/build-pages.py: edita la plantilla y vuelve a ejecutarlo. -->
<html lang="{lang}">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title}</title>
  <meta name="description" content="{description}">
{hreflangs}
  <link rel="icon" href="{favicon}">
  <link rel="stylesheet" href="../css/style.css">
</head>
<body>
  <header class="hero">
    <div class="wrap">
      <nav class="lang" aria-label="{nav_label}">
        {nav}
      </nav>
      <p class="eyebrow">{eyebrow}</p>
      <h1>{h1}</h1>
      <p class="lead">{lead}</p>
    </div>
  </header>

  <main class="wrap">
    <section class="card" id="input-card">
      <h2>{step1}</h2>
      <div class="grid-2">
        <div>
          <label class="dropzone" id="dropzone" for="file-input" tabindex="0">
            <input type="file" id="file-input" accept=".ini,text/plain,*/*" hidden>
            <span class="drop-icon" aria-hidden="true">⇪</span>
            <span>{drop}</span>
            <span class="muted" id="file-name">{nofile}</span>
          </label>
          <div class="row">
            <button type="button" class="btn secondary" id="btn-sample">{sample}</button>
            <button type="button" class="btn secondary" id="btn-clear">{clear}</button>
          </div>
        </div>
        <div>
          <label for="version">{version_label}</label>
          <select id="version">
            <option value="unknown">{v_unknown}</option>
{options}
          </select>
          <p class="help">{version_help}</p>
          <label for="ini-text">{paste_label}</label>
          <textarea id="ini-text" rows="10" spellcheck="false" placeholder="{placeholder}"></textarea>
          <div class="row">
            <button type="button" class="btn primary" id="btn-analyze">{analyze}</button>
          </div>
        </div>
      </div>
    </section>

    <section class="card hidden" id="result-card">
      <h2>{step2}</h2>
      <div id="version-banner" class="banner"></div>
      <div class="summary" id="summary"></div>
      <table class="findings" id="findings">
        <thead>
          <tr>
{ths}
          </tr>
        </thead>
        <tbody></tbody>
      </table>
      <div class="row">
        <button type="button" class="btn primary" id="btn-download">{download}</button>
        <button type="button" class="btn secondary" id="btn-copy">{copy}</button>
        <button type="button" class="btn secondary" id="btn-toggle-preview">{preview}</button>
      </div>
      <pre class="preview hidden" id="preview"></pre>
    </section>

    <section class="card" id="about-card">
      <h2>{about}</h2>
      <div id="rules-doc"></div>
      <p class="muted">{sources}</p>
    </section>
  </main>

  <footer class="wrap muted">{footer}</footer>

  <script src="../js/analyzer.js"></script>
  <script src="../js/locale-{lang}.js"></script>
  <script src="../js/sample.js"></script>
  <script src="../js/app.js"></script>
</body>
</html>
"""


def build(lang, t):
    hreflangs = "\n".join(f'  <link rel="alternate" hreflang="{c}" href="../{c}/">' for c in LANGS)
    nav = " · ".join(
        f'<span aria-current="page">{LANGS[c]["name"]}</span>' if c == lang
        else f'<a href="../{c}/" hreflang="{c}" lang="{c}">{LANGS[c]["name"]}</a>'
        for c in LANGS
    )
    options = [f'            <option value="{v}">{t["v_fixed"].format(v=v, fix=fix)}</option>' for v, fix in FIXED]
    options += [f'            <option value="{v}">{t["v_eol"].format(v=v)}</option>' for v in EOL]
    options += [f'            <option value="old">{t["v_old"]}</option>']
    ths = "\n".join(f"            <th>{h}</th>" for h in t["th"])
    html = TEMPLATE.format(lang=lang, hreflangs=hreflangs, nav=nav, options="\n".join(options), ths=ths, favicon=FAVICON, **t)
    out = ROOT / lang / "index.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    print("escrito", out.relative_to(ROOT.parent))


if __name__ == "__main__":
    for lang, t in LANGS.items():
        build(lang, t)
