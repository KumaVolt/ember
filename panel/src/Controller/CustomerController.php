<?php

namespace App\Controller;

use App\Service\EmberApi;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

final class CustomerController extends AbstractController
{
    public function __construct(private readonly EmberApi $api)
    {
    }

    #[Route('/customers', name: 'customers', methods: ['GET'])]
    public function index(): Response
    {
        return $this->render('customer/index.html.twig', [
            'customers' => ($this->api->get('/api/v1/customers')['customers'] ?? []),
        ]);
    }

    #[Route('/customers/new', name: 'customer_new', methods: ['GET'])]
    public function new(): Response
    {
        return $this->render('customer/new.html.twig');
    }

    #[Route('/customers/new', name: 'customer_create', methods: ['POST'])]
    public function create(Request $request): Response
    {
        $result = $this->api->post('/api/v1/customers', [
            'username' => trim((string) $request->request->get('username')),
            'display_name' => trim((string) $request->request->get('display_name')),
            'email' => trim((string) $request->request->get('email')),
        ]);

        if (null === $result || isset($result['error'])) {
            $this->addFlash('error', $result['error'] ?? 'Ember did not respond.');

            return $this->redirectToRoute('customer_new');
        }

        $this->addFlash('ok', sprintf(
            'Customer <strong>%s</strong> created.',
            htmlspecialchars($result['username'])
        ));

        return $this->redirectToRoute('customers');
    }

    #[Route('/customers/{id}/delete', name: 'customer_delete', methods: ['POST'], requirements: ['id' => '\d+'])]
    public function delete(int $id): Response
    {
        $result = $this->api->delete('/api/v1/customers/'.$id);

        if (null === $result || isset($result['error'])) {
            $this->addFlash('error', $result['error'] ?? 'Ember did not respond.');
        } else {
            $this->addFlash('ok', sprintf('Removed <strong>%s</strong>.', htmlspecialchars($result['removed'])));
        }

        return $this->redirectToRoute('customers');
    }
}
