<?php

namespace App\Controller;

use App\Service\EmberApi;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Settings, and the sections under it.
 *
 * Nothing here touches the machine directly. Installing a package, restarting
 * the server and saving branding all go through the control API, which is the
 * only tier with the privileges — and the guards — to do any of it.
 */
final class SettingsController extends AbstractController
{
    public function __construct(private readonly EmberApi $api)
    {
    }

    #[Route('/settings', name: 'settings', methods: ['GET'])]
    public function index(): Response
    {
        return $this->render('settings/index.html.twig');
    }

    // --- server management -------------------------------------------------

    #[Route('/settings/server', name: 'settings_server', methods: ['GET'])]
    public function server(): Response
    {
        $system = $this->api->get('/api/v1/system') ?? [];

        return $this->render('settings/server.html.twig', [
            'stats' => $system['stats'] ?? [],
            'mode' => $system['mode'] ?? 'isolated',
        ]);
    }

    #[Route('/settings/server/updates', name: 'settings_updates', methods: ['GET'])]
    public function updates(): Response
    {
        // Checking reaches out to GitHub and the package manager, so it happens
        // when this page is opened rather than on every page load.
        return $this->render('settings/updates.html.twig', [
            'updates' => $this->api->get('/api/v1/updates') ?? [],
        ]);
    }

    #[Route('/settings/server/power', name: 'settings_power', methods: ['POST'])]
    public function power(Request $request): Response
    {
        $result = $this->api->post('/api/v1/system/power', [
            'action' => (string) $request->request->get('action'),
            'confirm' => trim((string) $request->request->get('confirm')),
        ]);

        if (null === $result || isset($result['error'])) {
            $this->addFlash('error', $result['error'] ?? 'Ember did not respond.');
        } else {
            $this->addFlash('ok', htmlspecialchars($result['result']));
        }

        return $this->redirectToRoute('settings_server');
    }

    // --- services ----------------------------------------------------------

    #[Route('/settings/services', name: 'settings_services', methods: ['GET'])]
    public function services(): Response
    {
        $result = $this->api->get('/api/v1/services') ?? [];

        // Grouped here rather than in the template: the catalogue decides its
        // own categories, and the view should not have to know them.
        $grouped = [];
        foreach ($result['services'] ?? [] as $service) {
            $grouped[$service['category']][] = $service;
        }

        $queue = $this->api->get('/api/v1/jobs') ?? [];

        return $this->render('settings/services.html.twig', [
            'grouped' => $grouped,
            'engines' => $result['engines'] ?? [],
            'node_versions' => $result['node_versions'] ?? [],
            'node_installed' => $result['node_installed'] ?? null,
            'jobs' => $queue['jobs'] ?? [],
            'busy' => $queue['busy'] ?? false,
            'lock_held_by' => $queue['package_lock_held_by'] ?? null,
        ]);
    }

    #[Route('/settings/services/install', name: 'settings_service_install', methods: ['POST'])]
    public function install(Request $request): Response
    {
        $payload = [];
        if ($engine = $request->request->get('engine')) {
            $payload['engine'] = (string) $engine;
        } elseif ($node = $request->request->get('node')) {
            $payload['node'] = (string) $node;
        } else {
            $payload['id'] = (string) $request->request->get('id');
        }

        $result = $this->api->post('/api/v1/services/install', $payload);

        if (null === $result || isset($result['error'])) {
            $this->addFlash('error', $result['error'] ?? 'Ember did not respond.');
        } else {
            // The work is queued, not done — say that rather than implying it
            // finished.
            $this->addFlash('ok', sprintf(
                '<strong>%s</strong> queued. It runs in the background; this page follows along.',
                htmlspecialchars($result['job']['label'] ?? 'Install'),
            ));
        }

        return $this->redirectToRoute('settings_services');
    }

    // --- appearance --------------------------------------------------------

    #[Route('/settings/appearance', name: 'settings_appearance', methods: ['GET'])]
    public function appearance(): Response
    {
        return $this->render('settings/appearance.html.twig', [
            'branding' => $this->api->get('/api/v1/branding') ?? [],
        ]);
    }

    #[Route('/settings/appearance', name: 'settings_appearance_save', methods: ['POST'])]
    public function saveAppearance(Request $request): Response
    {
        $result = $this->api->post('/api/v1/branding', [
            'name' => trim((string) $request->request->get('name')),
            'tagline' => trim((string) $request->request->get('tagline')),
            'accent' => trim((string) $request->request->get('accent')),
            'logo_url' => trim((string) $request->request->get('logo_url')),
        ]);

        if (null === $result || isset($result['error'])) {
            $this->addFlash('error', $result['error'] ?? 'Ember did not respond.');
        } else {
            $this->addFlash('ok', 'Appearance saved.');
        }

        return $this->redirectToRoute('settings_appearance');
    }
}
