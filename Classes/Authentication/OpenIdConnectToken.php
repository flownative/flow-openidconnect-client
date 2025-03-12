<?php
declare(strict_types=1);
namespace Flownative\OpenIdConnect\Client\Authentication;

use Flownative\OpenIdConnect\Client\ConnectionException;
use Flownative\OpenIdConnect\Client\IdentityToken;
use Flownative\OpenIdConnect\Client\OAuthClient;
use Flownative\OpenIdConnect\Client\OpenIdConnectClient;
use Flownative\OpenIdConnect\Client\ServiceException;
use Neos\Flow\Mvc\ActionRequest;
use Neos\Flow\Security\Authentication\Token\AbstractToken;
use Neos\Flow\Security\Authentication\Token\SessionlessTokenInterface;
use Neos\Flow\Security\Authentication\TokenInterface;
use Neos\Flow\Security\Exception\AccessDeniedException;
use Neos\Flow\Security\Exception\AuthenticationRequiredException;
use Neos\Flow\Security\Exception\InvalidAuthenticationStatusException;

final class OpenIdConnectToken extends AbstractToken implements SessionlessTokenInterface
{
    /**
     * Name of the parameter used internally by this OpenID Connect client package in GET query parts
     */
    public const OIDC_PARAMETER_NAME = 'flownative_oidc';

    protected array $queryParameters = [];

    protected array $cookies = [];

    protected string $authorizationHeader = '';

    /**
     * @throws InvalidAuthenticationStatusException
     */
    public function updateCredentials(ActionRequest $actionRequest): void
    {
        $this->setAuthenticationStatus(self::AUTHENTICATION_NEEDED);
        $httpRequest = $actionRequest->getHttpRequest();

        $this->queryParameters = $httpRequest->getQueryParams();
        $this->cookies = $httpRequest->getCookieParams();

        if ($httpRequest->hasHeader('Authorization')) {
            $this->authorizationHeader = current($httpRequest->getHeader('Authorization'));
        }
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
        if ($this->authorizationHeader !== '' && str_contains($this->authorizationHeader, 'Bearer ')) {
            $identityToken = $this->extractIdentityTokenFromAuthorizationHeader($this->authorizationHeader);
        } elseif (isset($this->queryParameters[self::OIDC_PARAMETER_NAME])) {
            $authorizationIdQueryParameterName = OAuthClient::generateAuthorizationIdQueryParameterName(OAuthClient::SERVICE_TYPE);
            if (!isset($this->queryParameters[$authorizationIdQueryParameterName])) {
                throw new AccessDeniedException(sprintf('Missing authorization identifier "%s" from query parameters', $authorizationIdQueryParameterName), 1560350311);
            }
            try {
                $tokenArguments = TokenArguments::fromSignedString($this->queryParameters[self::OIDC_PARAMETER_NAME]);
            } catch (\InvalidArgumentException $exception) {
                $this->setAuthenticationStatus(self::WRONG_CREDENTIALS);
                throw new AccessDeniedException('Could not extract token arguments from query parameters', 1560349658, $exception);
            }

            $authorizationIdentifier = $this->queryParameters[$authorizationIdQueryParameterName];
            $client = new OpenIdConnectClient($tokenArguments[TokenArguments::SERVICE_NAME]);

            try {
                $identityToken = $client->getIdentityToken($authorizationIdentifier);
                $client->removeAuthorization($authorizationIdentifier);
            } catch (ServiceException | ConnectionException $exception) {
                throw new AccessDeniedException(sprintf('Could not extract identity token for authorization identifier "%s": %s', $authorizationIdentifier, $exception->getMessage()), 1560350413, $exception);
            }
        } else {
            $identityToken = $this->extractIdentityTokenFromCookie($cookieName);
        }

        // NOTE: This token is not verified yet – signature and expiration time must be checked by code using this token
        return $identityToken;
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
        } catch (\InvalidArgumentException $exception) {
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
        } catch (\InvalidArgumentException $exception) {
            $this->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
            throw new AuthenticationRequiredException(sprintf('Could not extract JWT from cookie "%s"', $cookieName), 1560349541, $exception);
        }
        return $identityToken;
    }
}
