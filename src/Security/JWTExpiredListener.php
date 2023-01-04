<?php

namespace K3\JwtAuth\Security;

use Lexik\Bundle\JWTAuthenticationBundle\Event\JWTExpiredEvent;
use Lexik\Bundle\JWTAuthenticationBundle\Response\JWTAuthenticationFailureResponse;

class JWTExpiredListener
{
    public function onJWTExpired(JWTExpiredEvent $event): void
    {
        $response = new JWTAuthenticationFailureResponse('Sessione scaduta', 401);

        $event->setResponse($response);
    }
}
