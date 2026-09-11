<?php
declare(strict_types=1);
namespace Flownative\OpenIdConnect\Client\Authentication;

use Flownative\OpenIdConnect\Client\ConnectionException;
use Flownative\OpenIdConnect\Client\IdentityToken;
use Flownative\OpenIdConnect\Client\OAuthClient;
use Flownative\OpenIdConnect\Client\OpenIdConnectClientFactory;
use Flownative\OpenIdConnect\Client\ServiceException;
use InvalidArgumentException;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Mvc\ActionRequest;
use Neos\Flow\Security\Authentication\Token\AbstractToken;
use Neos\Flow\Security\Authentication\Token\SessionlessTokenInterface;
use Neos\Flow\Security\Authentication\TokenInterface;
use Neos\Flow\Security\Cryptography\HashService;
use Neos\Flow\Security\Exception\AccessDeniedException;
use Neos\Flow\Security\Exception\AuthenticationRequiredException;
use Neos\Flow\Security\Exception\InvalidAuthenticationStatusException;

final class OpenIdConnectToken extends AbstractToken implements SessionlessTokenInterface
{
    /**
     * Name of the parameter used internally by this OpenID Connect client package in GET query parts
     */
    public const string OIDC_PARAMETER_NAME = 'flownative_oidc';

    protected array $queryParameters = [];

    protected array $cookies = [];

    protected string $authorizationHeader = '';

    protected string $refreshToken = '';

    protected bool $bearerAuthorizationHeaderGiven = false;

    #[Flow\Inject]
    protected OpenIdConnectClientFactory $openIdConnectClientFactory;

    #[Flow\Inject]
    protected HashService $hashService;

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
        } elseif (isset($this->queryParameters[self::OIDC_PARAMETER_NAME])) {
            $authorizationIdQueryParameterName = OAuthClient::generateAuthorizationIdQueryParameterName(OAuthClient::SERVICE_TYPE);
            if (!isset($this->queryParameters[$authorizationIdQueryParameterName])) {
                throw new AccessDeniedException(sprintf('Missing authorization identifier "%s" from query parameters', $authorizationIdQueryParameterName), 1560350311);
            }
            $signedTokenArguments = $this->queryParameters[self::OIDC_PARAMETER_NAME];
            $authorizationIdentifier = $this->queryParameters[$authorizationIdQueryParameterName];
            if (!is_string($signedTokenArguments) || !is_string($authorizationIdentifier)) {
                $this->setAuthenticationStatus(self::WRONG_CREDENTIALS);
                throw new AccessDeniedException('The OpenID Connect query parameters are not strings', 1789122178);
            }
            try {
                $tokenArguments = TokenArguments::fromSignedString($signedTokenArguments, $this->hashService);
            } catch (InvalidArgumentException $exception) {
                $this->setAuthenticationStatus(self::WRONG_CREDENTIALS);
                throw new AccessDeniedException('Could not extract token arguments from query parameters', 1560349658, $exception);
            }

            // Creating the client may already contact the identity provider for discovery. The messages of the caught
            // exceptions may contain the authorization identifier from the query, so they are not repeated here.
            try {
                $client = $this->openIdConnectClientFactory->create($tokenArguments[TokenArguments::SERVICE_NAME]);
                $tokenSet = $client->getIdentityToken($authorizationIdentifier);
                $identityToken = $tokenSet->identityToken;
                $this->refreshToken = $tokenSet->refreshToken;
                $client->removeAuthorization($authorizationIdentifier);
            } catch (ServiceException | ConnectionException $exception) {
                throw new AccessDeniedException('Could not retrieve the identity token of the finished authorization', 1560350413, $exception);
            }
        } else {
            $identityToken = $this->extractIdentityTokenFromCookie($cookieName);
        }

        // NOTE: This token is not verified yet – signature and expiration time must be checked by code using this token
        return $identityToken;
    }

    public function getRefreshToken(): string
    {
        return $this->refreshToken;
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
