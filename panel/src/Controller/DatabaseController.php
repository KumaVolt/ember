<?php

namespace App\Controller;

use App\Service\EmberApi;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Customer databases.
 *
 * The panel holds no database credential of its own and never speaks to
 * MariaDB. Everything goes through the control API, which is the only thing
 * that can administer the server.
 */
final class DatabaseController extends AbstractController
{
    public function __construct(private readonly EmberApi $api)
    {
    }

    #[Route('/databases', name: 'databases', methods: ['GET'])]
    public function index(): Response
    {
        $result = $this->api->get('/api/v1/databases') ?? [];

        return $this->render('database/index.html.twig', [
            'databases' => $result['databases'] ?? [],
            'server' => $result['server'] ?? ['available' => false, 'status' => 'unknown'],
        ]);
    }

    /**
     * Databases for one domain.
     *
     * A database may belong to a specific site or to the customer generally,
     * so this shows both: the ones attached to this domain, and the owner's
     * others, which that site can still legitimately use.
     */
    #[Route('/domains/{id}/databases', name: 'domain_databases', methods: ['GET'], requirements: ['id' => '\d+'])]
    public function forDomain(int $id): Response
    {
        $domain = $this->api->get('/api/v1/domains/'.$id);
        if (null === $domain || isset($domain['error'])) {
            $this->addFlash('error', 'That domain no longer exists.');

            return $this->redirectToRoute('domains');
        }

        $all = $this->api->get('/api/v1/databases?customer_id='.$domain['customer_id']) ?? [];
        $owned = [];
        $others = [];
        foreach ($all['databases'] ?? [] as $database) {
            if (($database['domain_id'] ?? null) === $id) {
                $owned[] = $database;
            } else {
                $others[] = $database;
            }
        }

        return $this->render('database/domain.html.twig', [
            'domain' => $domain,
            'databases' => $owned,
            'others' => $others,
            'server' => $all['server'] ?? ['available' => false, 'status' => 'unknown'],
        ]);
    }

    #[Route('/domains/{id}/databases/new', name: 'domain_database_create', methods: ['POST'], requirements: ['id' => '\d+'])]
    public function createForDomain(int $id, Request $request): Response
    {
        // Only the domain is named; Ember resolves the owner from it.
        $result = $this->api->post('/api/v1/databases', [
            'domain_id' => $id,
            'name' => trim((string) $request->request->get('name')),
            'engine' => (string) $request->request->get('engine', 'mariadb'),
        ]);

        if (null === $result || isset($result['error'])) {
            $this->addFlash('error', $result['error'] ?? 'Ember did not respond.');
        } else {
            $this->addFlash('ok', sprintf(
                'Database <strong>%s</strong> created.<ul>'
                .'<li>User: <code>%s</code></li>'
                .'<li>Password: <code>%s</code></li>'
                .'<li>Host: <code>127.0.0.1</code> or <code>localhost</code></li>'
                .'</ul>Copy the password now — it is not stored and cannot be shown again.',
                htmlspecialchars($result['database']['name']),
                htmlspecialchars($result['database']['db_user']),
                htmlspecialchars($result['password']),
            ));
        }

        return $this->redirectToRoute('domain_databases', ['id' => $id]);
    }

    #[Route('/databases/new', name: 'database_new', methods: ['GET'])]
    public function new(): Response
    {
        return $this->render('database/new.html.twig', [
            'customers' => ($this->api->get('/api/v1/customers')['customers'] ?? []),
            'server' => ($this->api->get('/api/v1/databases')['server'] ?? ['available' => false]),
        ]);
    }

    #[Route('/databases/new', name: 'database_create', methods: ['POST'])]
    public function create(Request $request): Response
    {
        $result = $this->api->post('/api/v1/databases', [
            'customer_id' => (int) $request->request->get('customer_id'),
            'name' => trim((string) $request->request->get('name')),
            'engine' => (string) $request->request->get('engine', 'mariadb'),
        ]);

        if (null === $result || isset($result['error'])) {
            $this->addFlash('error', $result['error'] ?? 'Ember did not respond.');

            return $this->redirectToRoute('database_new');
        }

        // Shown once. Ember does not store it, so there is no way to display
        // it again — only to reset it.
        $this->addFlash('ok', sprintf(
            'Database <strong>%s</strong> created.<ul>'
            .'<li>User: <code>%s</code></li>'
            .'<li>Password: <code>%s</code></li>'
            .'<li>Host: <code>127.0.0.1</code> or <code>localhost</code></li>'
            .'</ul>Copy the password now — it is not stored and cannot be shown again.',
            htmlspecialchars($result['database']['name']),
            htmlspecialchars($result['database']['db_user']),
            htmlspecialchars($result['password']),
        ));

        return $this->redirectToRoute('databases');
    }

    #[Route('/databases/{id}/password', name: 'database_password', methods: ['POST'], requirements: ['id' => '\d+'])]
    public function resetPassword(int $id): Response
    {
        $result = $this->api->post('/api/v1/databases/'.$id.'/password', []);

        if (null === $result || isset($result['error'])) {
            $this->addFlash('error', $result['error'] ?? 'Ember did not respond.');
        } else {
            $this->addFlash('ok', sprintf(
                'New password for <code>%s</code>: <code>%s</code><br>'
                .'Copy it now — it is not stored.',
                htmlspecialchars($result['user']),
                htmlspecialchars($result['password']),
            ));
        }

        return $this->redirectToRoute('databases');
    }

    #[Route('/databases/{id}/reveal', name: 'database_reveal', methods: ['POST'], requirements: ['id' => '\d+'])]
    public function reveal(int $id, Request $request): Response
    {
        $result = $this->api->get('/api/v1/databases/'.$id.'/reveal');

        if (null === $result || isset($result['error'])) {
            $this->addFlash('error', $result['error'] ?? 'Ember did not respond.');
        } else {
            $this->addFlash('ok', sprintf(
                'Password for <code>%s</code>: <code>%s</code>',
                htmlspecialchars($result['user']),
                htmlspecialchars($result['password']),
            ));
        }

        // Back where the button was pressed, which may be a domain page.
        $back = (string) $request->request->get('back', '');

        return $this->redirect('' !== $back && str_starts_with($back, '/') ? $back : $this->generateUrl('databases'));
    }

    #[Route('/databases/{id}/delete', name: 'database_delete_confirm', methods: ['GET'], requirements: ['id' => '\d+'])]
    public function confirmDelete(int $id): Response
    {
        $databases = $this->api->get('/api/v1/databases')['databases'] ?? [];
        foreach ($databases as $database) {
            if ($database['id'] === $id) {
                return $this->render('database/delete.html.twig', ['database' => $database]);
            }
        }

        $this->addFlash('error', 'That database no longer exists.');

        return $this->redirectToRoute('databases');
    }

    #[Route('/databases/{id}/delete', name: 'database_delete', methods: ['POST'], requirements: ['id' => '\d+'])]
    public function delete(int $id, Request $request): Response
    {
        // Ember does the matching; checking only here would leave the API open.
        $confirm = trim((string) $request->request->get('confirm'));
        $result = $this->api->delete('/api/v1/databases/'.$id.'?confirm='.rawurlencode($confirm));

        if (null !== $result && isset($result['error'])) {
            $this->addFlash('error', $result['error']);

            return $this->redirectToRoute('database_delete_confirm', ['id' => $id]);
        }

        $this->addFlash('ok', sprintf('Dropped <strong>%s</strong>.', htmlspecialchars($result['removed'] ?? '')));

        return $this->redirectToRoute('databases');
    }
}
