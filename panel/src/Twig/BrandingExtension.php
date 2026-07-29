<?php

namespace App\Twig;

use App\Service\EmberApi;
use Twig\Extension\AbstractExtension;
use Twig\Extension\GlobalsInterface;

/**
 * Makes the operator's branding available to every template.
 *
 * White-labelling is a config change on the server, not a template edit, so the
 * panel reads the same values the sign-in page does.
 */
final class BrandingExtension extends AbstractExtension implements GlobalsInterface
{
    /** @var array<string, mixed>|null */
    private ?array $cached = null;

    public function __construct(private readonly EmberApi $api)
    {
    }

    public function getGlobals(): array
    {
        // Resolved once per request. The worker is resident, so this must not
        // persist across requests or a rebrand would need a restart.
        $this->cached ??= $this->api->get('/api/v1/branding') ?? [];

        return [
            'brand' => [
                'name' => $this->cached['name'] ?? 'Ember',
                'tagline' => $this->cached['tagline'] ?? 'Server control panel',
                'accent' => $this->cached['accent'] ?? '#2563eb',
                'logo_url' => $this->cached['logo_url'] ?? null,
            ],
        ];
    }
}
