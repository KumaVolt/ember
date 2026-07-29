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

    #[Route('/domains/new', name: 'domain_new', methods: ['GET'])]
    public function new(): Response
    {
        return $this->render('domain/new.html.twig', [
            'customers' => ($this->api->get('/api/v1/customers')['customers'] ?? []),
        ]);
    }

    #[Route('/domains/new', name: 'domain_create', methods: ['POST'])]
    public function create(Request $request): Response
    {
        $result = $this->api->post('/api/v1/domains', [
            'name' => trim((string) $request->request->get('name')),
            'customer_id' => (int) $request->request->get('customer_id'),
            'webserver' => (string) $request->request->get('webserver', 'nginx'),
        ]);

        if (null === $result || isset($result['error'])) {
            $this->addFlash('error', $result['error'] ?? 'Ember did not respond.');

            // Back to the form, not the list: the operator has something to fix.
            return $this->redirectToRoute('domain_new');
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

            // Back to the form, not the list: the operator has something to fix.
            return $this->redirectToRoute('domain_new');
        }

        $message = 'Certificate issued.';
        if (!empty($result['notes'])) {
            $message .= '<ul><li>'.implode('</li><li>', array_map('htmlspecialchars', $result['notes'])).'</li></ul>';
        }
        $this->addFlash('ok', $message);

        return $this->redirectToRoute('domains');
    }

    #[Route('/domains/{id}/hosting', name: 'domain_hosting', methods: ['GET'], requirements: ['id' => '\d+'])]
    public function hosting(int $id): Response
    {
        $domain = $this->api->get('/api/v1/domains/'.$id);
        if (null === $domain || isset($domain['error'])) {
            $this->addFlash('error', 'That domain no longer exists.');

            return $this->redirectToRoute('domains');
        }

        return $this->render('domain/hosting.html.twig', [
            'domain' => $domain,
            'hosting' => $this->api->get('/api/v1/domains/'.$id.'/hosting') ?? [],
        ]);
    }

    #[Route('/domains/{id}/hosting', name: 'domain_hosting_save', methods: ['POST'], requirements: ['id' => '\d+'])]
    public function saveHosting(int $id, Request $request): Response
    {
        $form = $request->request;

        $result = $this->api->post('/api/v1/domains/'.$id.'/hosting', [
            'document_root' => trim((string) $form->get('document_root')),
            'preferred_domain' => (string) $form->get('preferred_domain'),
            'additional_directives' => trim((string) $form->get('additional_directives')),
            'webserver' => (string) $form->get('webserver'),
            // Unticked checkboxes are absent, so each is read explicitly.
            'force_https' => $form->getBoolean('force_https'),
            'error_documents' => $form->getBoolean('error_documents'),
            'ssh_access' => $form->getBoolean('ssh_access'),
            'suspended' => $form->getBoolean('suspended'),
        ]);

        if (null === $result || isset($result['error'])) {
            $this->addFlash('error', $result['error'] ?? 'Ember did not respond.');
        } else {
            $message = 'Hosting settings saved.';
            if (!empty($result['notes'])) {
                $message .= '<ul><li>'.implode('</li><li>', array_map('htmlspecialchars', $result['notes'])).'</li></ul>';
            }
            $this->addFlash('ok', $message);
        }

        return $this->redirectToRoute('domain_hosting', ['id' => $id]);
    }

    #[Route('/domains/{id}/php', name: 'domain_php', methods: ['GET'], requirements: ['id' => '\d+'])]
    public function php(int $id): Response
    {
        $domain = $this->api->get('/api/v1/domains/'.$id);
        if (null === $domain || isset($domain['error'])) {
            $this->addFlash('error', 'That domain no longer exists.');

            return $this->redirectToRoute('domains');
        }

        return $this->render('domain/php.html.twig', [
            'domain' => $domain,
            'php' => $this->api->get('/api/v1/domains/'.$id.'/php') ?? [],
        ]);
    }

    #[Route('/domains/{id}/php', name: 'domain_php_save', methods: ['POST'], requirements: ['id' => '\d+'])]
    public function savePhp(int $id, Request $request): Response
    {
        $form = $request->request;

        // Checkboxes are absent when unticked, so each is read explicitly
        // rather than taken from whatever the form happened to send.
        $flags = ['file_uploads', 'display_errors', 'log_errors', 'allow_url_fopen',
                  'short_open_tag', 'opcache_enable', 'opcache_validate_timestamps'];
        $numbers = ['pm_max_children', 'pm_start_servers', 'pm_min_spare_servers',
                    'pm_max_spare_servers', 'pm_max_requests', 'pm_process_idle_timeout',
                    'max_execution_time', 'max_input_time', 'max_input_vars',
                    'opcache_memory_consumption', 'opcache_max_accelerated_files',
                    'opcache_revalidate_freq'];
        $strings = ['pm', 'memory_limit', 'post_max_size', 'upload_max_filesize',
                    'error_reporting', 'open_basedir', 'disable_functions',
                    'session_save_path', 'additional_directives'];

        $payload = ['version' => (string) $form->get('version', '')];
        foreach ($flags as $flag) {
            $payload[$flag] = $form->getBoolean($flag);
        }
        foreach ($numbers as $number) {
            $payload[$number] = (int) $form->get($number);
        }
        foreach ($strings as $string) {
            $payload[$string] = trim((string) $form->get($string));
        }

        $result = $this->api->post('/api/v1/domains/'.$id.'/php', $payload);

        if (null === $result || isset($result['error'])) {
            $this->addFlash('error', $result['error'] ?? 'Ember did not respond.');
        } else {
            $this->addFlash('ok', 'PHP settings saved. '.htmlspecialchars($result['result'] ?? ''));
        }

        return $this->redirectToRoute('domain_php', ['id' => $id]);
    }

    #[Route('/domains/{id}/delete', name: 'domain_delete_confirm', methods: ['GET'], requirements: ['id' => '\d+'])]
    public function confirmDelete(int $id): Response
    {
        $domain = $this->api->get('/api/v1/domains/'.$id);
        if (null === $domain || isset($domain['error'])) {
            $this->addFlash('error', 'That domain no longer exists.');

            return $this->redirectToRoute('domains');
        }

        $domain['certificate'] =
            $this->api->get('/api/v1/domains/'.$id.'/certificate')['certificate'] ?? null;

        return $this->render('domain/delete.html.twig', ['domain' => $domain]);
    }

    #[Route('/domains/{id}/delete', name: 'domain_delete', methods: ['POST'], requirements: ['id' => '\d+'])]
    public function delete(int $id, Request $request): Response
    {
        // Passed through to Ember, which does the matching itself. Checking it
        // only here would leave the API unguarded.
        $confirm = trim((string) $request->request->get('confirm'));
        $result = $this->api->delete('/api/v1/domains/'.$id.'?confirm='.rawurlencode($confirm));

        if (null !== $result && isset($result['error'])) {
            $this->addFlash('error', $result['error']);

            return $this->redirectToRoute('domain_delete_confirm', ['id' => $id]);
        }

        if (null === $result || isset($result['error'])) {
            $this->addFlash('error', $result['error'] ?? 'Ember did not respond.');
        } else {
            $this->addFlash('ok', sprintf('Removed <strong>%s</strong>.', htmlspecialchars($result['removed'])));
        }

        return $this->redirectToRoute('domains');
    }
}
