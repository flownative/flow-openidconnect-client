<?php
declare(strict_types=1);
namespace Flownative\OpenIdConnect\Client\Authentication;

use Flownative\OpenIdConnect\Client\IdentityToken;
use InvalidArgumentException;
use Neos\Flow\Mvc\ActionRequest;
use Neos\Flow\Security\Authentication\Token\SessionlessTokenInterface;
use Neos\Flow\Security\Authentication\TokenInterface;
use Neos\Flow\Security\Exception\AccessDeniedException;
use Neos\Flow\Security\Exception\AuthenticationRequiredException;
use Neos\Flow\Security\Exception\InvalidAuthenticationStatusException;

/**
 * Carries the login in a JWT cookie or in a bearer token, and is checked again on every request
 */
final class OpenIdConnectToken extends AbstractOpenIdConnectToken implements SessionlessTokenInterface
{
    protected string $authorizationHeader = '';

    protected bool $bearerAuthorizationHeaderGiven = false;

    /**
     * @throws InvalidAuthenticationStatusException
     */
    public function updateCredentials(ActionRequest $actionRequest): void
    {
        $this->setAuthenticationStatus(self::AUTHENTICATION_NEEDED);
        $httpRequest = $actionRequest->getHttpRequest();

        // Flow uses the same token instance for all requests handled by a process, so nothing of a previous request may remain
        $this->queryParameters = $httpRequest->getQueryParams();
        $this->cookies = $httpRequest->getCookieParams();
        $this->authorizationHeader = $httpRequest->getHeader('Authorization')[0] ?? '';
        $this->bearerAuthorizationHeaderGiven = str_contains($this->authorizationHeader, 'Bearer ');
        $this->refreshToken = '';
        $this->nonceCookieName = '';
    }

    /**
     * Extract an identity token from either the query parameters of the current request (in case we
     * just return from an authentication redirect) or from a given JWT cookie (for subsequent requests).
     *
     * @param string $cookieName Name of the cookie the token is stored in
     * @return IdentityToken A syntactically valid but not verified (signature, expiration) token
     * @throws AccessDeniedException
     * @throws AuthenticationRequiredException
     * @throws InvalidAuthenticationStatusException
     */
    public function extractIdentityTokenFromRequest(string $cookieName): IdentityToken
    {
        if ($this->bearerAuthorizationHeaderGiven) {
            $identityToken = $this->extractIdentityTokenFromAuthorizationHeader($this->authorizationHeader);
        } elseif ($this->isReturnFromIdentityProvider()) {
            $identityToken = $this->extractIdentityTokenFromFinishedAuthorization();
        } else {
            $identityToken = $this->extractIdentityTokenFromCookie($cookieName);
        }

        // NOTE: This token is not verified yet – signature and expiration time must be checked by code using this token
        return $identityToken;
    }

    /**
     * Tells if the request carries a bearer token in the "Authorization" header. The identity token is then only read from this header, even if it is invalid.
     */
    public function hasBearerAuthorizationHeader(): bool
    {
        return $this->bearerAuthorizationHeaderGiven;
    }

    /**
     * @throws AccessDeniedException | AuthenticationRequiredException | InvalidAuthenticationStatusException
     */
    private function extractIdentityTokenFromAuthorizationHeader(string $authorizationHeader): IdentityToken
    {
        if (!str_starts_with($authorizationHeader, 'Bearer ')) {
            $this->setAuthenticationStatus(TokenInterface::NO_CREDENTIALS_GIVEN);
            throw new AuthenticationRequiredException('Could not extract access token from Authorization header: "Bearer" keyword is missing', 1589283608);
        }

        try {
            $jwt = substr($authorizationHeader, strlen('Bearer '));
            $identityToken = IdentityToken::fromJwt($jwt);
        } catch (InvalidArgumentException $exception) {
            $this->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
            throw new AccessDeniedException('Could not extract JWT from Authorization header', 1589283968, $exception);
        }
        return $identityToken;
    }

    /**
     * @throws AuthenticationRequiredException
     * @throws InvalidAuthenticationStatusException
     */
    private function extractIdentityTokenFromCookie(string $cookieName): IdentityToken
    {
        $jwt = $this->cookies[$cookieName] ?? null;
        if (!is_string($jwt) || $jwt === '') {
            $this->setAuthenticationStatus(TokenInterface::NO_CREDENTIALS_GIVEN);
            throw new AuthenticationRequiredException(sprintf('Missing/empty cookie "%s"', $cookieName), 1560349409);
        }
        try {
            $identityToken = IdentityToken::fromJwt($jwt);
        } catch (InvalidArgumentException $exception) {
            $this->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
            throw new AuthenticationRequiredException(sprintf('Could not extract JWT from cookie "%s"', $cookieName), 1560349541, $exception);
        }
        return $identityToken;
    }
}
