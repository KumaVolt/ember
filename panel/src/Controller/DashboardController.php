<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

final class DashboardController extends AbstractController
{
    #[Route('/', name: 'dashboard', methods: ['GET'])]
    public function index(Request $request): Response
    {
        return $this->render('dashboard.html.twig', [
            'php_version' => PHP_VERSION,
            'sapi' => PHP_SAPI,
            'symfony_version' => \Symfony\Component\HttpKernel\Kernel::VERSION,
            'auth_type' => $request->server->get('AUTH_TYPE', 'unknown'),
            'status' => $this->emberStatus($request),
        ]);
    }

    /**
     * Ask Ember about the service it is running.
     *
     * The panel runs unprivileged and cannot inspect processes itself, so
     * anything at that level is delegated to Ember's control API. The session
     * cookie is forwarded because that API authenticates the same way the
     * browser does.
     *
     * @return array<string, mixed>|null
     */
    private function emberStatus(Request $request): ?array
    {
        $port = $request->server->get('SERVER_PORT', '7878');
        $cookie = $request->headers->get('cookie', '');

        $context = stream_context_create(['http' => [
            'method' => 'GET',
            'header' => "Cookie: {$cookie}\r\n",
            'timeout' => 2,
            'ignore_errors' => true,
        ]]);

        $body = @file_get_contents("http://127.0.0.1:{$port}/api/v1/status", false, $context);
        if (false === $body) {
            return null;
        }

        $decoded = json_decode($body, true);

        return is_array($decoded) ? $decoded : null;
    }
}
