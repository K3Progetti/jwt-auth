<?php

namespace K3\JwtAuth\Security;

use K3\User\Entity\K3User;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class UserChecker implements UserCheckerInterface
{
    public function checkPreAuth(UserInterface $user)
    {
        if (!$user instanceof K3User) {
            return;
        }

        // user is deleted, show a generic Account Not Found message.
        if (!$user->getActive()) {
            // or to customize the message shown
            throw new CustomUserMessageAuthenticationException(
                'Utente non attivo. Contattare l\'amministratore di sistema'
            );
        }
    }

    public function checkPostAuth(UserInterface $user)
    {
        if (!$user instanceof K3User) {
            return;
        }
    }
}
