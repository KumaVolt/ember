<?php

namespace App\Security;

use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

/**
 * Turns the REMOTE_USER that Ember set into a Symfony user.
 *
 * There is no user table to consult. Ember is the authority on identity — it
 * owns the PAM stack and the session signing key — and it strips any client
 * supplied Remote-User header, so an identity arriving here is trustworthy.
 *
 * @implements UserProviderInterface<EmberUser>
 */
final class EmberUserProvider implements UserProviderInterface
{
    public function loadUserByIdentifier(string $identifier): UserInterface
    {
        if ('' === trim($identifier)) {
            throw new UserNotFoundException('Ember supplied an empty identity.');
        }

        return new EmberUser($identifier, $this->rolesFor($identifier));
    }

    public function refreshUser(UserInterface $user): UserInterface
    {
        if (!$user instanceof EmberUser) {
            throw new UnsupportedUserException(sprintf('Unexpected user class "%s".', $user::class));
        }

        // Re-derive rather than trusting the old instance, so a role change
        // takes effect on the next request instead of persisting stale grants.
        return $this->loadUserByIdentifier($user->getUserIdentifier());
    }

    public function supportsClass(string $class): bool
    {
        return EmberUser::class === $class || is_subclass_of($class, EmberUser::class);
    }

    /**
     * @return list<string>
     */
    private function rolesFor(string $username): array
    {
        // Placeholder authorisation model. Ember's control API is the right
        // place to resolve real roles once the panel grows them.
        return 'root' === $username || 'admin' === $username
            ? ['ROLE_ADMIN', 'ROLE_USER']
            : ['ROLE_USER'];
    }
}
