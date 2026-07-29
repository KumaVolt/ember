<?php

namespace App\Controller;

use App\Service\EmberApi;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The file manager.
 *
 * Every path here is passed straight through to Ember, which resolves it
 * against the domain root and refuses anything that escapes. The panel never
 * joins paths or touches the filesystem — doing either would put the check in
 * the tier with the least business holding it.
 */
final class FileController extends AbstractController
{
    public function __construct(private readonly EmberApi $api)
    {
    }

    #[Route('/domains/{id}/files', name: 'domain_files', methods: ['GET'], requirements: ['id' => '\d+'])]
    public function browse(int $id, Request $request): Response
    {
        $domain = $this->api->get('/api/v1/domains/'.$id);
        if (null === $domain || isset($domain['error'])) {
            $this->addFlash('error', 'That domain no longer exists.');

            return $this->redirectToRoute('domains');
        }

        $path = $request->query->get('path', '/');
        $listing = $this->api->get('/api/v1/domains/'.$id.'/files?path='.rawurlencode($path));

        if (null === $listing || isset($listing['error'])) {
            $this->addFlash('error', $listing['error'] ?? 'Could not read that directory.');
            $listing = ['path' => '/', 'parent' => null, 'entries' => []];
        }

        // Editing opens in the same page, so the file is fetched here rather
        // than through a second round trip from the browser.
        $editing = null;
        if ($file = $request->query->get('edit')) {
            $read = $this->api->get('/api/v1/domains/'.$id.'/files/read?path='.rawurlencode($file));
            if (null !== $read && !isset($read['error'])) {
                $editing = $read;
            } else {
                $this->addFlash('error', $read['error'] ?? 'Could not open that file.');
            }
        }

        return $this->render('domain/files.html.twig', [
            'domain' => $domain,
            'listing' => $listing,
            'editing' => $editing,
            'crumbs' => $this->crumbs($listing['path'] ?? '/'),
        ]);
    }

    #[Route('/domains/{id}/files/save', name: 'domain_file_save', methods: ['POST'], requirements: ['id' => '\d+'])]
    public function save(int $id, Request $request): Response
    {
        $path = (string) $request->request->get('path');
        $result = $this->api->post('/api/v1/domains/'.$id.'/files/write', [
            'path' => $path,
            'content' => (string) $request->request->get('content'),
        ]);

        $this->flash($result, sprintf('Saved <strong>%s</strong>.', htmlspecialchars($path)));

        return $this->redirectToRoute('domain_files', [
            'id' => $id,
            'path' => \dirname($path),
            'edit' => $path,
        ]);
    }

    #[Route('/domains/{id}/files/mkdir', name: 'domain_file_mkdir', methods: ['POST'], requirements: ['id' => '\d+'])]
    public function mkdir(int $id, Request $request): Response
    {
        $dir = rtrim((string) $request->request->get('path'), '/');
        $name = trim((string) $request->request->get('name'), '/');

        $result = $this->api->post('/api/v1/domains/'.$id.'/files/mkdir', [
            'path' => $dir.'/'.$name,
        ]);
        $this->flash($result, sprintf('Created <strong>%s</strong>.', htmlspecialchars($name)));

        return $this->redirectToRoute('domain_files', ['id' => $id, 'path' => $dir ?: '/']);
    }

    #[Route('/domains/{id}/files/new', name: 'domain_file_new', methods: ['POST'], requirements: ['id' => '\d+'])]
    public function create(int $id, Request $request): Response
    {
        $dir = rtrim((string) $request->request->get('path'), '/');
        $name = trim((string) $request->request->get('name'), '/');
        $path = $dir.'/'.$name;

        $result = $this->api->post('/api/v1/domains/'.$id.'/files/write', [
            'path' => $path,
            'content' => '',
        ]);
        $this->flash($result, sprintf('Created <strong>%s</strong>.', htmlspecialchars($name)));

        return $this->redirectToRoute('domain_files', [
            'id' => $id,
            'path' => $dir ?: '/',
            'edit' => $path,
        ]);
    }

    #[Route('/domains/{id}/files/rename', name: 'domain_file_rename', methods: ['POST'], requirements: ['id' => '\d+'])]
    public function rename(int $id, Request $request): Response
    {
        $path = (string) $request->request->get('path');
        $name = trim((string) $request->request->get('name'), '/');
        $dir = \dirname($path);

        $result = $this->api->post('/api/v1/domains/'.$id.'/files/rename', [
            'path' => $path,
            'to' => ('/' === $dir ? '' : $dir).'/'.$name,
        ]);
        $this->flash($result, sprintf('Renamed to <strong>%s</strong>.', htmlspecialchars($name)));

        return $this->redirectToRoute('domain_files', ['id' => $id, 'path' => $dir]);
    }

    #[Route('/domains/{id}/files/delete', name: 'domain_file_delete', methods: ['POST'], requirements: ['id' => '\d+'])]
    public function delete(int $id, Request $request): Response
    {
        $path = (string) $request->request->get('path');
        $result = $this->api->delete('/api/v1/domains/'.$id.'/files?path='.rawurlencode($path));
        $this->flash($result, sprintf('Deleted <strong>%s</strong>.', htmlspecialchars($path)));

        return $this->redirectToRoute('domain_files', ['id' => $id, 'path' => \dirname($path)]);
    }

    /** @param array<string, mixed>|null $result */
    private function flash(?array $result, string $success): void
    {
        if (null === $result || isset($result['error'])) {
            $this->addFlash('error', $result['error'] ?? 'Ember did not respond.');

            return;
        }
        $this->addFlash('ok', $success);
    }

    /**
     * Breadcrumb segments, each with the path that navigates to it.
     *
     * @return list<array{name: string, path: string}>
     */
    private function crumbs(string $path): array
    {
        $crumbs = [['name' => 'root', 'path' => '/']];
        $walked = '';
        foreach (array_filter(explode('/', $path)) as $segment) {
            $walked .= '/'.$segment;
            $crumbs[] = ['name' => $segment, 'path' => $walked];
        }

        return $crumbs;
    }
}
