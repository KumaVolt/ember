<?php

namespace App\Controller;

use App\Service\EmberApi;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

final class DashboardController extends AbstractController
{
    public function __construct(private readonly EmberApi $api)
    {
    }

    #[Route('/', name: 'dashboard', methods: ['GET'])]
    public function index(): Response
    {
        return $this->render('dashboard.html.twig', [
            'summary' => $this->api->get('/api/v1/summary') ?? ['customers' => 0, 'domains' => 0],
            'status' => $this->api->get('/api/v1/status'),
            'domains' => ($this->api->get('/api/v1/domains')['domains'] ?? []),
        ]);
    }

    #[Route('/system', name: 'system', methods: ['GET'])]
    public function system(): Response
    {
        return $this->render('system.html.twig', [
            'status' => $this->api->get('/api/v1/status'),
            'whoami' => $this->api->get('/api/v1/whoami'),
            'users' => ($this->api->get('/api/v1/users')['users'] ?? []),
            'php_version' => PHP_VERSION,
            'symfony_version' => \Symfony\Component\HttpKernel\Kernel::VERSION,
        ]);
    }
}
