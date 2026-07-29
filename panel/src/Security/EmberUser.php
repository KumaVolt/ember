<?php

namespace App\Security;

use Symfony\Component\Security\Core\User\UserInterface;

/**
 * A panel user, as vouched for by Ember.
 *
 * Carries no credential: Ember authenticated the account before this request
 * reached PHP, either against the system password database via PAM or against
 * its own setup/recovery store. The panel only ever learns *who* is signed in.
 */
final class EmberUser implements UserInterface
{
    public function __construct(
        private readonly string $username,
        private readonly array $roles = ['ROLE_USER'],
    ) {
    }

    public function getUserIdentifier(): string
    {
        return $this->username;
    }

    public function getRoles(): array
    {
        // ROLE_USER is always implied so a misconfigured role list cannot
        // accidentally produce a user with no roles at all.
        return array_unique([...$this->roles, 'ROLE_USER']);
    }

    public function eraseCredentials(): void
    {
        // Nothing to erase — this user never held a credential.
    }
}
