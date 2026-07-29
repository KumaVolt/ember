<?php
/**
 * Placeholder front controller for the Ember panel.
 *
 * Replace this whole directory with a Laravel or Symfony app — Ember serves
 * whatever `public/index.php` it finds here, so the framework install is a
 * drop-in with no changes on the Rust side.
 */

$required = ['pdo', 'mbstring', 'openssl', 'tokenizer', 'xml', 'curl', 'session', 'fileinfo'];
$missing  = array_values(array_filter($required, fn($e) => !extension_loaded($e)));
?>
<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Ember</title>
<style>
  :root { color-scheme: dark; }
  body { margin: 0; padding: 3rem 1.5rem; background: #0e0f12; color: #e6e8ee;
         font: 15px/1.6 ui-sans-serif, system-ui, -apple-system, sans-serif; }
  main { max-width: 46rem; margin: 0 auto; }
  h1 { font-size: 1.6rem; margin: 0 0 .25rem; letter-spacing: -.02em; }
  h1 span { color: #ff7a45; }
  p.lead { margin: 0 0 2.5rem; color: #8b90a0; }
  .card { border: 1px solid #23252c; border-radius: 10px; padding: 1.25rem 1.5rem; margin-bottom: 1rem; background: #14161a; }
  .card h2 { font-size: .75rem; text-transform: uppercase; letter-spacing: .08em;
             color: #8b90a0; margin: 0 0 .9rem; font-weight: 600; }
  dl { display: grid; grid-template-columns: 11rem 1fr; gap: .45rem 1rem; margin: 0; }
  dt { color: #8b90a0; }
  dd { margin: 0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .85rem; word-break: break-all; }
  .ok { color: #4ade80; } .warn { color: #fbbf24; }
</style>
<main>
  <h1>Ember<span>.</span></h1>
  <p class="lead">Server control panel — running on its own PHP runtime.</p>

  <div class="card">
    <h2>PHP runtime</h2>
    <dl>
      <dt>Version</dt><dd><?= htmlspecialchars(PHP_VERSION) ?></dd>
      <dt>SAPI</dt><dd><?= htmlspecialchars(PHP_SAPI) ?></dd>
      <dt>Binary</dt><dd><?= htmlspecialchars(PHP_BINARY ?: 'n/a') ?></dd>
      <dt>Loaded php.ini</dt><dd><?= htmlspecialchars(php_ini_loaded_file() ?: 'none') ?></dd>
      <dt>Extensions</dt>
      <dd><?= $missing
            ? '<span class="warn">missing: ' . htmlspecialchars(implode(', ', $missing)) . '</span>'
            : '<span class="ok">all Laravel prerequisites present</span>' ?></dd>
    </dl>
  </div>

  <div class="card">
    <h2>Request</h2>
    <dl>
      <dt>Method</dt><dd><?= htmlspecialchars($_SERVER['REQUEST_METHOD'] ?? '?') ?></dd>
      <dt>URI</dt><dd><?= htmlspecialchars($_SERVER['REQUEST_URI'] ?? '?') ?></dd>
      <dt>Document root</dt><dd><?= htmlspecialchars($_SERVER['DOCUMENT_ROOT'] ?? '?') ?></dd>
      <dt>Server software</dt><dd><?= htmlspecialchars($_SERVER['SERVER_SOFTWARE'] ?? '?') ?></dd>
    </dl>
  </div>

  <div class="card">
    <h2>Next step</h2>
    <p style="margin:0;color:#8b90a0">
      Install Laravel or Symfony into <code style="color:#e6e8ee">~/.ember/panel</code>
      so that <code style="color:#e6e8ee">public/index.php</code> is the framework's
      front controller. Ember will serve it unchanged.
    </p>
  </div>
</main>
