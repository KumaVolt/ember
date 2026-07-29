<?php

namespace App\Controller;

use App\Service\EmberApi;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

final class DomainController extends AbstractController
{
    public function __construct(private readonly EmberApi $api)
    {
    }

    #[Route('/domains', name: 'domains', methods: ['GET'])]
    public function index(): Response
    {
        $domains = $this->api->get('/api/v1/domains')['domains'] ?? [];

        // Certificate state lives with certbot, not in the panel's records, so
        // it is asked for per domain rather than stored and risking drift.
        foreach ($domains as $i => $domain) {
            $domains[$i]['certificate'] =
                $this->api->get('/api/v1/domains/'.$domain['id'].'/certificate')['certificate'] ?? null;
        }

        return $this->render('domain/index.html.twig', [
            'domains' => $domains,
            'customers' => ($this->api->get('/api/v1/customers')['customers'] ?? []),
        ]);
    }

    #[Route('/domains/new', name: 'domain_new', methods: ['POST'])]
    public function create(Request $request): Response
    {
        $result = $this->api->post('/api/v1/domains', [
            'name' => trim((string) $request->request->get('name')),
            'customer_id' => (int) $request->request->get('customer_id'),
            'webserver' => (string) $request->request->get('webserver', 'nginx'),
        ]);

        if (null === $result || isset($result['error'])) {
            $this->addFlash('error', $result['error'] ?? 'Ember did not respond.');

            return $this->redirectToRoute('domains');
        }

        // Ember reports what it could and could not do — writing the vhost,
        // reloading the web server. Surfacing that beats a bare success.
        $message = sprintf('<strong>%s</strong> created.', htmlspecialchars($result['domain']['name']));
        if (!empty($result['notes'])) {
            $message .= '<ul><li>'.implode('</li><li>', array_map('htmlspecialchars', $result['notes'])).'</li></ul>';
        }
        $this->addFlash('ok', $message);

        return $this->redirectToRoute('domains');
    }

    /**
     * Request a certificate.
     *
     * The panel does not run certbot and does not touch /etc/letsencrypt — it
     * asks Ember over the control API, which is the only thing privileged
     * enough to do either.
     */
    #[Route('/domains/{id}/certificate', name: 'domain_certificate', methods: ['POST'], requirements: ['id' => '\d+'])]
    public function certificate(int $id, Request $request): Response
    {
        $result = $this->api->post('/api/v1/domains/'.$id.'/certificate', [
            'staging' => (bool) $request->request->get('staging'),
        ]);

        if (null === $result || isset($result['error'])) {
            $this->addFlash('error', $result['error'] ?? 'Ember did not respond.');

            return $this->redirectToRoute('domains');
        }

        $message = 'Certificate issued.';
        if (!empty($result['notes'])) {
            $message .= '<ul><li>'.implode('</li><li>', array_map('htmlspecialchars', $result['notes'])).'</li></ul>';
        }
        $this->addFlash('ok', $message);

        return $this->redirectToRoute('domains');
    }

    #[Route('/domains/{id}/delete', name: 'domain_delete', methods: ['POST'], requirements: ['id' => '\d+'])]
    public function delete(int $id): Response
    {
        $result = $this->api->delete('/api/v1/domains/'.$id);

        if (null === $result || isset($result['error'])) {
            $this->addFlash('error', $result['error'] ?? 'Ember did not respond.');
        } else {
            $this->addFlash('ok', sprintf('Removed <strong>%s</strong>.', htmlspecialchars($result['removed'])));
        }

        return $this->redirectToRoute('domains');
    }
}
