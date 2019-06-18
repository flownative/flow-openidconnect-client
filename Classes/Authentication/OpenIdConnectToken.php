<?php
declare(strict_types = 1);
namespace Flownative\OpenIdConnect\Client\Authentication;

use Flownative\OAuth2\Client\OAuthClient;
use Flownative\OpenIdConnect\Client\ConnectionException;
use Flownative\OpenIdConnect\Client\IdentityToken;
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

    /**
     * @var array
     */
    protected $queryParameters;

    /**
     * @var array
     */
    protected $cookies = [];

    /**
     * @param ActionRequest $actionRequest
     * @throws InvalidAuthenticationStatusException
     */
    public function updateCredentials(ActionRequest $actionRequest): void
    {
        $this->setAuthenticationStatus(self::AUTHENTICATION_NEEDED);
        $httpRequest = $actionRequest->getHttpRequest();

        $this->queryParameters = $httpRequest->getQueryParams();
        $this->cookies = $httpRequest->getCookieParams();
    }

    /**
     * @param string $cookieName
     * @return IdentityToken
     * @throws AccessDeniedException
     * @throws AuthenticationRequiredException
     * @throws InvalidAuthenticationStatusException
     */
    public function extractIdentityToken(string $cookieName): IdentityToken
    {
        if (isset($this->queryParameters[self::OIDC_PARAMETER_NAME])) {
            if (!isset($this->queryParameters[OAuthClient::STATE_QUERY_PARAMETER_NAME])) {
                throw new AccessDeniedException(sprintf('Missing authorization identifier "%s" from query parameters', OAuthClient::STATE_QUERY_PARAMETER_NAME), 1560350311);
            }
            try {
                $tokenArguments = TokenArguments::fromSignedString($this->queryParameters[self::OIDC_PARAMETER_NAME]);
            } catch (\InvalidArgumentException $exception) {
                $this->setAuthenticationStatus(self::WRONG_CREDENTIALS);
                throw new AccessDeniedException('Could not extract token arguments from query parameters', 1560349658, $exception);
            }

            $authorizationIdentifier = $this->queryParameters[OAuthClient::STATE_QUERY_PARAMETER_NAME];
            $client = new OpenIdConnectClient($tokenArguments[TokenArguments::SERVICE_NAME]);

            try {
                return $client->getIdentityToken($authorizationIdentifier);
            } catch (ServiceException | ConnectionException $exception) {
                throw new AccessDeniedException(sprintf('Could not extract identity token for authorization identifier "%s"', $authorizationIdentifier), 1560350413, $exception);
            }
        }

        return $this->extractIdentityTokenFromCookie($cookieName);
    }

    /**
     * @param string $cookieName
     * @return IdentityToken
     * @throws AccessDeniedException | AuthenticationRequiredException | InvalidAuthenticationStatusException
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
            throw new AccessDeniedException(sprintf('Could not extract JWT from cookie "%s"', $cookieName), 1560349541, $exception);
        }
        return $identityToken;
    }
}
