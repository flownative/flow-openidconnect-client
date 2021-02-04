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
     * @Flow\InjectConfiguration(path="middleware")
     * @var array
     */
    protected $options;

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
        if (!$this->isOpenIdConnectAuthentication()) {
            return $response;
        }

        $account = $this->securityContext->getAccountByAuthenticationProviderName($this->options['authenticationProviderName']);
        if ($account === null) {
            if (isset($request->getCookieParams()[$this->options['cookie']['name']])) {
                $this->logger->debug(sprintf('OpenID Connect: No account is authenticated using the provider %s, removing JWT cookie "%s".', $this->options['authenticationProviderName'], $this->options['cookie']['name']), LogEnvironment::fromMethodName(__METHOD__));
                return $this->removeJwtCookie($response);
            }
            return $response;
        }

        $identityToken = $account->getCredentialsSource();
        if (!$identityToken instanceof IdentityToken) {
            $this->logger->error(sprintf('OpenID Connect: No identity token found in credentials source of account %s - could not set JWT cookie.', $account->getAccountIdentifier()), LogEnvironment::fromMethodName(__METHOD__));
            return $response;
        }

        return $this->setJwtCookie($response, $identityToken->asJwt());
    }

    /**
     * @return bool
     */
    private function isOpenIdConnectAuthentication(): bool
    {
        foreach ($this->securityContext->getAuthenticationTokensOfType(OpenIdConnectToken::class) as $token) {
            if ($token->getAuthenticationProviderName() === $this->options['authenticationProviderName']) {
                return true;
            }
        }
        return false;
    }

    /**
     * @param ResponseInterface $response
     * @param string $jwt
     * @return ResponseInterface
     */
    private function setJwtCookie(ResponseInterface $response, string $jwt): ResponseInterface
    {
        $jwtCookie = new Cookie($this->options['cookie']['name'], $jwt, 0, null, null, '/', $this->options['cookie']['secure'], false, $this->options['cookie']['sameSite']);
        return $response->withAddedHeader('Set-Cookie', (string)$jwtCookie);
    }

    /**
     * @param ResponseInterface $response
     * @return ResponseInterface
     */
    private function removeJwtCookie(ResponseInterface $response): ResponseInterface
    {
        $emptyJwtCookie = new Cookie($this->options['cookie']['name'], '', 1, null, null, '/', $this->options['cookie']['secure'], false, $this->options['cookie']['sameSite']);
        return $response->withAddedHeader('Set-Cookie', (string)$emptyJwtCookie);
    }
}
