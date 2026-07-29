<?php

/**
 * esw-engine worker — a resident Symfony process.
 *
 * Ember spawns this with stdin and stdout piped, then feeds it one request at a
 * time. The kernel boots once and survives; only per-request state is reset.
 * That removes the bootstrap that FPM pays on every single request.
 *
 * Framing in both directions is:
 *
 *     [4 bytes BE header length][4 bytes BE body length][header JSON][body]
 *
 * stdout carries the protocol and nothing else. Anything the application prints
 * would corrupt the stream, so output is buffered per request and diagnostics
 * go to stderr, which Ember relays into its log.
 *
 * This deliberately boots the kernel by hand rather than through
 * symfony/runtime: the runtime captures an app callable by re-including the
 * entry script, which would run this file twice.
 */

use App\Kernel;
use Symfony\Component\Dotenv\Dotenv;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\TerminableInterface;

ini_set('display_errors', 'stderr');
ini_set('log_errors', '1');

$root = dirname(__DIR__);
require $root.'/vendor/autoload.php';

if (class_exists(Dotenv::class) && is_file($root.'/.env')) {
    (new Dotenv())->bootEnv($root.'/.env');
}

final class EswWorker
{
    private mixed $resetter = null;

    public function __construct(
        private readonly Kernel $kernel,
        private readonly mixed $in,
        private readonly mixed $out,
    ) {
        $container = $kernel->getContainer();
        if ($container->has('esw.services_resetter')) {
            $this->resetter = $container->get('esw.services_resetter');
        }
    }

    public function run(): void
    {
        fwrite(STDERR, 'ready (pid '.getmypid().')'.PHP_EOL);

        while (null !== $frame = $this->readFrame()) {
            [$meta, $body] = $frame;

            try {
                $response = $this->handle($meta, $body);
            } catch (\Throwable $e) {
                fwrite(STDERR, sprintf(
                    '%s: %s in %s:%d%s',
                    $e::class, $e->getMessage(), $e->getFile(), $e->getLine(), PHP_EOL
                ));
                $response = new Response(
                    "Internal Server Error\n", 500, ['Content-Type' => 'text/plain']
                );
            }

            $this->writeResponse($response);

            // Drop per-request state so the next request starts clean.
            // Without this, request-scoped services leak between requests.
            if (null !== $this->resetter) {
                $this->resetter->reset();
            }
        }
    }

    /**
     * @return array{0: array<string, mixed>, 1: string}|null
     */
    private function readFrame(): ?array
    {
        $prefix = $this->readExactly(8);
        if (null === $prefix) {
            return null; // Ember closed the pipe: shut down cleanly.
        }

        ['h' => $headerLength, 'b' => $bodyLength] = unpack('Nh/Nb', $prefix);

        $header = $headerLength > 0 ? $this->readExactly($headerLength) : '';
        $body = $bodyLength > 0 ? $this->readExactly($bodyLength) : '';
        if (null === $header || null === $body) {
            return null;
        }

        return [json_decode($header, true, 32, JSON_THROW_ON_ERROR), $body];
    }

    private function readExactly(int $length): ?string
    {
        $buffer = '';
        while (strlen($buffer) < $length) {
            $chunk = fread($this->in, $length - strlen($buffer));
            if (false === $chunk || '' === $chunk) {
                if (feof($this->in)) {
                    return null;
                }
                continue;
            }
            $buffer .= $chunk;
        }

        return $buffer;
    }

    /**
     * @param array<string, mixed> $meta
     */
    private function handle(array $meta, string $body): Response
    {
        // $_SERVER is rebuilt per request. Ember supplies REMOTE_USER here, and
        // the security firewall reads it straight out of the server bag.
        $server = $meta['server'] ?? [];

        $request = Request::create(
            $meta['uri'] ?? '/',
            $meta['method'] ?? 'GET',
            [],
            $meta['cookies'] ?? [],
            [],
            is_array($server) ? $server : [],
            '' === $body ? null : $body,
        );

        foreach (($meta['headers'] ?? []) as $name => $value) {
            $request->headers->set($name, $value);
        }

        $response = $this->kernel->handle($request);

        if ($this->kernel instanceof TerminableInterface) {
            $this->kernel->terminate($request, $response);
        }

        return $response;
    }

    private function writeResponse(Response $response): void
    {
        // Capture anything the response echoes so it becomes the body rather
        // than leaking into the protocol stream.
        ob_start();
        $response->sendContent();
        $content = ob_get_clean();

        $headers = [];
        foreach ($response->headers->allPreserveCase() as $name => $values) {
            $headers[$name] = array_values($values);
        }
        foreach ($response->headers->getCookies() as $cookie) {
            $headers['Set-Cookie'][] = (string) $cookie;
        }

        $header = json_encode([
            'status' => $response->getStatusCode(),
            'headers' => $headers,
        ], JSON_THROW_ON_ERROR);

        fwrite($this->out, pack('NN', strlen($header), strlen($content)));
        fwrite($this->out, $header);
        fwrite($this->out, $content);
        fflush($this->out);
    }
}

$kernel = new Kernel($_SERVER['APP_ENV'] ?? 'prod', (bool) ($_SERVER['APP_DEBUG'] ?? false));
$kernel->boot();

$in = fopen('php://stdin', 'rb');
$out = fopen('php://stdout', 'wb');
stream_set_blocking($in, true);

(new EswWorker($kernel, $in, $out))->run();
