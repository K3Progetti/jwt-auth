<?php

namespace K3\JwtAuth\Security;

use Doctrine\Common\EventSubscriber;
use Doctrine\ORM\Event\LifecycleEventArgs;
use K3\User\Entity\K3User;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface;

final class HashPasswordListener implements EventSubscriber
{
    /** @var UserPasswordEncoderInterface */
    private $passwordEncoder;

    /**
     * HashPasswordListener constructor.
     * @param UserPasswordEncoderInterface $passwordEncoder
     */
    public function __construct(UserPasswordEncoderInterface $passwordEncoder)
    {
        $this->passwordEncoder = $passwordEncoder;
    }

    /**
     * @param LifecycleEventArgs $args
     * @return void
     */
    public function prePersist(LifecycleEventArgs $args): void
    {
        $entity = $args->getEntity();
        if (!$entity instanceof K3User) {
            return;
        }

        $this->encodePassword($entity);
    }

    /**
     * @param LifecycleEventArgs $args
     * @return void
     */
    public function preUpdate(LifecycleEventArgs $args): void
    {
        $entity = $args->getEntity();
        if (!$entity instanceof K3User) {
            return;
        }

        $this->encodePassword($entity);
        // necessary to force the update to see the change
        $entityManager = $args->getEntityManager();
        $meta = $entityManager->getClassMetadata(\get_class($entity));
        $entityManager->getUnitOfWork()->recomputeSingleEntityChangeSet($meta, $entity);
    }

    /**
     * {@inheritdoc}
     */
    public function getSubscribedEvents()
    {
        return ['prePersist', 'preUpdate'];
    }

    /**
     * @param K3User $entity
     * @return void
     */
    private function encodePassword(K3User $entity): void
    {
        if ($entity->getPlainPassword() === null) {
            return;
        }

        $encoded = $this->passwordEncoder->encodePassword(
            $entity,
            $entity->getPlainPassword()
        );

        $entity->setPassword($encoded);
    }
}
