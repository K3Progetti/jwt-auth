<?php

namespace K3\JwtAuth\Security;

use K3\User\Entity\K3User;
use Lexik\Bundle\JWTAuthenticationBundle\Event\JWTCreatedEvent;

class JWTCreatedListener
{
    public function onJwtCreated(JWTCreatedEvent $event): void
    {
        /** @var K3User $user */
        $user = $event->getUser();

        $payload = $event->getData();
        $payload['id'] = $user->getId();

        $event->setData($payload);
    }
}
