<?php
declare(strict_types=1);
namespace Flownative\OpenIdConnect\Client\Authentication;

use Flownative\OAuth2\Client\UnknownAuthorizationHandleException;
use Flownative\OpenIdConnect\Client\ConnectionException;
use Flownative\OpenIdConnect\Client\CookieSettings;
use Flownative\OpenIdConnect\Client\IdentityToken;
use Flownative\OpenIdConnect\Client\OAuthClient;
use Flownative\OpenIdConnect\Client\OpenIdConnectClientFactory;
use Flownative\OpenIdConnect\Client\ServiceException;
use InvalidArgumentException;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Security\Authentication\Token\AbstractToken;
use Neos\Flow\Security\Cryptography\HashService;
use Neos\Flow\Security\Exception\AccessDeniedException;
use Neos\Flow\Security\Exception\InvalidAuthenticationStatusException;

/**
 * Takes the identity token of an authorization which the browser has just finished at the identity provider
 *
 * Both tokens of this package share these checks: the JWT token, which keeps the login in a cookie, and the session token.
 */
abstract class AbstractOpenIdConnectToken extends AbstractToken
{
    /**
     * Name of the parameter used internally by this OpenID Connect client package in GET query parts
     */
    public const string OIDC_PARAMETER_NAME = 'flownative_oidc';

    /**
     * The values of a request are transient, because Flow stores a token which is not sessionless in the session
     */
    #[Flow\Transient]
    protected array $queryParameters = [];

    #[Flow\Transient]
    protected array $cookies = [];

    #[Flow\Transient]
    protected string $refreshToken = '';

    #[Flow\Transient]
    protected string $nonceCookieName = '';

    #[Flow\Inject]
    protected OpenIdConnectClientFactory $openIdConnectClientFactory;

    #[Flow\Inject]
    protected HashService $hashService;

    #[Flow\InjectConfiguration(path: 'middleware')]
    protected array $middlewareSettings = [];

    public function getRefreshToken(): string
    {
        return $this->refreshToken;
    }

    /**
     * Returns the name of the nonce cookie which bound the finished authorization to this browser, or an empty string
     */
    public function getNonceCookieName(): string
    {
        return $this->nonceCookieName;
    }

    /**
     * Tells if the identity token comes from an authorization which this browser has just finished at the identity provider
     */
    public function hasFinishedAuthorization(): bool
    {
        return $this->nonceCookieName !== '';
    }

    /**
     * Tells if the browser returns from the identity provider with this request
     */
    protected function isReturnFromIdentityProvider(): bool
    {
        return isset($this->queryParameters[self::OIDC_PARAMETER_NAME]);
    }

    /**
     * Claims the finished authorization, and checks that it was started in this browser for the nonce in the identity token
     *
     * @return IdentityToken A syntactically valid but not verified (signature, claims) token
     * @throws AccessDeniedException
     * @throws InvalidAuthenticationStatusException
     */
    protected function extractIdentityTokenFromFinishedAuthorization(): IdentityToken
    {
        $authorizationIdQueryParameterName = OAuthClient::generateAuthorizationIdQueryParameterName(OAuthClient::SERVICE_TYPE);
        if (!isset($this->queryParameters[$authorizationIdQueryParameterName])) {
            throw new AccessDeniedException(sprintf('Missing authorization identifier "%s" from query parameters', $authorizationIdQueryParameterName), 1560350311);
        }
        $signedTokenArguments = $this->queryParameters[self::OIDC_PARAMETER_NAME];
        $authorizationHandle = $this->queryParameters[$authorizationIdQueryParameterName];
        if (!is_string($signedTokenArguments) || !is_string($authorizationHandle)) {
            $this->setAuthenticationStatus(self::WRONG_CREDENTIALS);
            throw new AccessDeniedException('The OpenID Connect query parameters are not strings', 1789122178);
        }
        try {
            $tokenArguments = TokenArguments::fromSignedString($signedTokenArguments, $this->hashService);
        } catch (InvalidArgumentException $exception) {
            $this->setAuthenticationStatus(self::WRONG_CREDENTIALS);
            throw new AccessDeniedException('Could not extract token arguments from query parameters', 1560349658, $exception);
        }

        // Creating the client may already contact the identity provider for discovery
        try {
            $client = $this->openIdConnectClientFactory->create($tokenArguments[TokenArguments::SERVICE_NAME]);
            $tokenSet = $client->getIdentityToken($authorizationHandle, $this->cookies);
        } catch (UnknownAuthorizationHandleException $exception) {
            $this->setAuthenticationStatus(self::WRONG_CREDENTIALS);
            throw new AccessDeniedException('The finished authorization is unknown, has expired or was not started in this browser', 1789395654, $exception);
        } catch (ServiceException | ConnectionException $exception) {
            throw new AccessDeniedException('Could not retrieve the identity token of the finished authorization', 1560350413, $exception);
        }

        $nonce = $tokenSet->identityToken->values['nonce'] ?? null;
        if (!is_string($nonce)) {
            $this->setAuthenticationStatus(self::WRONG_CREDENTIALS);
            throw new AccessDeniedException('The identity token of the finished authorization contains no nonce, although the authentication request sent one', 1789131857);
        }
        // The nonce must be the one of this authorization, and its secret must be in this browser
        $expectedNonce = $tokenArguments[TokenArguments::NONCE];
        $cookieSettings = CookieSettings::fromMiddlewareSettings($this->middlewareSettings);
        if (!is_string($expectedNonce) || !hash_equals($expectedNonce, $nonce) || !Nonce::isBoundToCookies($nonce, $this->cookies, $cookieSettings)) {
            $this->setAuthenticationStatus(self::WRONG_CREDENTIALS);
            throw new AccessDeniedException('The finished authorization was not started in this browser', 1789131856);
        }
        $this->refreshToken = $tokenSet->refreshToken;
        $this->nonceCookieName = Nonce::getCookieNameForValue($nonce, $cookieSettings);
        return $tokenSet->identityToken;
    }
}
