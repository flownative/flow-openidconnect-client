<?php
declare(strict_types=1);
namespace Flownative\OpenIdConnect\Client\Http;

use Flownative\OpenIdConnect\Client\Authentication\OpenIdConnectToken;
use Flownative\OpenIdConnect\Client\IdentityToken;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Http\Cookie;
use Neos\Flow\Log\Utility\LogEnvironment;
use Neos\Flow\Security\Context as SecurityContext;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;

final class SetJwtCookieMiddleware implements MiddlewareInterface
{
    /**
     * @Flow\Inject
     * @var SecurityContext
     */
    protected $securityContext;

    /**
     * @Flow\Inject
     * @var LoggerInterface
     */
    protected $logger;

    /**
     * @var array
     */
    private $options;

    /**
     * @var array
     */
    private $authenticationProviderConfiguration;

    public function __construct(array $options, array $authenticationProviderConfiguration)
    {
        $this->options = $options;
        $this->authenticationProviderConfiguration = $authenticationProviderConfiguration;
    }

    /**
     * @return void
     */
    public function initializeObject(): void
    {
        if (isset($this->options['cookieName'])) {
            $this->logger->warning('OpenID Connect: Option "cookieName" was used - please use "cookie.name" instead.', LogEnvironment::fromMethodName(__METHOD__));
            $this->options['cookie']['name'] = $this->options['cookieName'];
        }
        if (isset($this->options['secureCookie'])) {
            $this->logger->warning('OpenID Connect: Option "secureCookie" was used - please use "cookie.secure" instead.', LogEnvironment::fromMethodName(__METHOD__));
            $this->options['cookie']['secure'] = $this->options['secureCookie'];
        }
    }

    /**
     * @param ServerRequestInterface $request
     * @param RequestHandlerInterface $handler
     * @return ResponseInterface
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $response = $handler->handle($request);

        if (!$this->securityContext->isInitialized() && !$this->securityContext->canBeInitialized()) {
            $this->logger->debug('OpenID Connect: Cannot send JWT cookie because the security context could not be initialized.', LogEnvironment::fromMethodName(__METHOD__));
            return $response;
        }
        foreach ($this->securityContext->getAuthenticationTokensOfType(OpenIdConnectToken::class) as $token) {
            $providerName = $token->getAuthenticationProviderName();
            $providerOptions = $this->authenticationProviderConfiguration[$token->getAuthenticationProviderName()]['providerOptions'] ?? [];
            $account = $this->securityContext->getAccountByAuthenticationProviderName($providerName);
            $cookieName = $providerOptions['jwtCookieName'] ?? $this->options['cookie']['name'] ?? 'flownative_oidc_jwt';
            $cookieSecure = $this->options['cookie']['secure'] ?? true;
            $cookieHttpOnly = $this->options['cookie']['httpOnly'] ?? false;
            $cookieSameSite = $this->options['cookie']['sameSite'] ?? 'strict';
            if ($account === null) {
                if (isset($request->getCookieParams()[$cookieName])) {
                    $this->logger->debug(sprintf('OpenID Connect: No account is authenticated using the provider %s, removing JWT cookie "%s".', $providerName, $cookieName), LogEnvironment::fromMethodName(__METHOD__));
                    $response = $this->removeJwtCookie($response, $cookieName, $cookieSecure, $cookieHttpOnly, $cookieSameSite);
                }
                continue;
            }
            $identityToken = $account->getCredentialsSource();
            if (!$identityToken instanceof IdentityToken) {
                $this->logger->error(sprintf('OpenID Connect: No identity token found in credentials source of account %s - could not set JWT cookie.', $account->getAccountIdentifier()), LogEnvironment::fromMethodName(__METHOD__));
                continue;
            }

            $response = $this->setJwtCookie($response, $cookieName, $cookieSecure, $cookieHttpOnly, $cookieSameSite, $identityToken->asJwt());
        }
        return $response;
    }

    /**
     * @param ResponseInterface $response
     * @param string $cookieName
     * @param bool $secure
     * @param bool $httpOnly
     * @param string $sameSite
     * @param string $jwt
     * @return ResponseInterface
     */
    private function setJwtCookie(ResponseInterface $response, string $cookieName, bool $secure, bool $httpOnly, string $sameSite, string $jwt): ResponseInterface
    {
        $jwtCookie = new Cookie($cookieName, $jwt, 0, null, null, '/', $secure, $httpOnly, $sameSite);
        return $response->withAddedHeader('Set-Cookie', (string)$jwtCookie);
    }

    /**
     * @param ResponseInterface $response
     * @param string $cookieName
     * @param bool $secure
     * @param bool $httpOnly
     * @param string $sameSite
     * @return ResponseInterface
     */
    private function removeJwtCookie(ResponseInterface $response, string $cookieName, bool $secure, bool $httpOnly, string $sameSite): ResponseInterface
    {
        $emptyJwtCookie = new Cookie($cookieName, '', 1, null, null, '/', $secure, $httpOnly, $sameSite);
        return $response->withAddedHeader('Set-Cookie', (string)$emptyJwtCookie);
    }
}
