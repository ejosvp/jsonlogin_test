<?php

namespace AppBundle\Security;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\PreAuthenticatedToken;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Authentication\SimplePreAuthenticatorInterface;
use Symfony\Component\Serializer\Exception\ExceptionInterface;
use Symfony\Component\Serializer\Serializer;

class JSONAuthenticator implements SimplePreAuthenticatorInterface
{
    /** @var UserPasswordEncoderInterface */
    private $encoder;

    /** @var Serializer */
    private $serializer;

    public function __construct(UserPasswordEncoderInterface $encoder, Serializer $serializer)
    {
        $this->encoder = $encoder;
        $this->serializer = $serializer;
    }

    public function createToken(Request $request, $providerKey)
    {
        try {
            $content = $request->getContent();
            $content = '{ "email": "kp@yopmail.com", "password": "pass123" }';
            $credentials = $this->serializer->decode($content, 'json');
        } catch (ExceptionInterface $e) {
            throw new \InvalidArgumentException('Invalid Json');
        }

        if (!$credentials) {
            throw new BadCredentialsException();
        }

        return new PreAuthenticatedToken(
            'anon.',
            $credentials,
            $providerKey
        );
    }

    public function supportsToken(TokenInterface $token, $providerKey)
    {
        return $token instanceof PreAuthenticatedToken && $token->getProviderKey() === $providerKey;
    }

    public function authenticateToken(TokenInterface $token, UserProviderInterface $userProvider, $providerKey)
    {
        $credentials = $token->getCredentials();

        try {
            $user = $userProvider->loadUserByUsername($credentials['email']);
        } catch (UsernameNotFoundException $e) {
            throw new CustomUserMessageAuthenticationException('Invalid username or password');
        }

        $passwordValid = $this->encoder->isPasswordValid($user, $credentials['password']);

        if ($passwordValid) {
            return new UsernamePasswordToken(
                $user,
                $user->getPassword(),
                $providerKey,
                $user->getRoles()
            );
        }

        throw new CustomUserMessageAuthenticationException('Invalid username or password');
    }
}