<?php

namespace App\Service;

use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Client for Ember's control API.
 *
 * The panel holds no database credential and never touches the store directly.
 * Everything it knows, it asks Ember for — so a fault in this tier cannot read
 * or corrupt the records, only make calls Ember is willing to authorise.
 *
 * The caller's session cookie is forwarded, so the API applies exactly the same
 * permissions the browser has. The panel cannot act with more authority than
 * the person using it.
 */
final class EmberApi
{
    public function __construct(private readonly RequestStack $requests)
    {
    }

    /** @return array<string, mixed>|null */
    public function get(string $path): ?array
    {
        return $this->call('GET', $path);
    }

    /** @param array<string, mixed> $payload @return array<string, mixed>|null */
    public function post(string $path, array $payload): ?array
    {
        return $this->call('POST', $path, $payload);
    }

    /** @return array<string, mixed>|null */
    public function delete(string $path): ?array
    {
        return $this->call('DELETE', $path);
    }

    /**
     * @param array<string, mixed>|null $payload
     * @return array<string, mixed>|null
     */
    private function call(string $method, string $path, ?array $payload = null): ?array
    {
        $request = $this->requests->getCurrentRequest();
        $port = $request?->server->get('SERVER_PORT', '7878') ?? '7878';
        $cookie = $request?->headers->get('cookie', '') ?? '';

        $headers = ["Cookie: {$cookie}", 'Accept: application/json'];
        $options = [
            'method' => $method,
            'timeout' => 10,
            // Read the body on 4xx/5xx too: the API puts the reason there, and
            // showing it beats a generic failure message.
            'ignore_errors' => true,
        ];

        if (null !== $payload) {
            $headers[] = 'Content-Type: application/json';
            $options['content'] = json_encode($payload, JSON_THROW_ON_ERROR);
        }

        $options['header'] = implode("\r\n", $headers)."\r\n";

        $body = @file_get_contents(
            "http://127.0.0.1:{$port}{$path}",
            false,
            stream_context_create(['http' => $options]),
        );

        if (false === $body) {
            return null;
        }

        $decoded = json_decode($body, true);

        return is_array($decoded) ? $decoded : null;
    }
}
