<?php
declare(strict_types=1);
namespace Flownative\OpenIdConnect\Client\Http;

use Flownative\OpenIdConnect\Client\Authentication\OpenIdConnectToken;
use Flownative\OpenIdConnect\Client\IdentityToken;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Http\Component\ComponentContext;
use Neos\Flow\Http\Component\ComponentInterface;
use Neos\Flow\Http\Cookie;
use Neos\Flow\Log\Utility\LogEnvironment;
use Neos\Flow\Security\Context as SecurityContext;
use Psr\Log\LoggerInterface;

final class SetJwtCookieComponent implements ComponentInterface
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
     * @param array|null $options
     */
    public function __construct(array $options = null)
    {
        $this->options = $options;
    }

    /**
     *
     */
    public function initializeObject()
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
     * @param ComponentContext $componentContext
     */
    public function handle(ComponentContext $componentContext): void
    {
        if (!$this->securityContext->isInitialized() && !$this->securityContext->canBeInitialized()) {
            $this->logger->debug('OpenID Connect: Cannot send JWT cookie because the security context could not be initialized.', LogEnvironment::fromMethodName(__METHOD__));
            return;
        }
        if (!$this->isOpenIdConnectAuthentication()) {
            return;
        }
        $account = $this->securityContext->getAccountByAuthenticationProviderName($this->options['authenticationProviderName']);
        if ($account === null) {
            $this->logger->debug(sprintf('OpenID Connect: No account is authenticated using the provider %s, removing JWT cookie "%s" if it exists.', $this->options['authenticationProviderName'], $this->options['cookie']['name']), LogEnvironment::fromMethodName(__METHOD__));
            $this->removeJwtCookie($componentContext);
            return;
        }

        $identityToken = $account->getCredentialsSource();
        if (!$identityToken instanceof IdentityToken) {
            $this->logger->error(sprintf('OpenID Connect: No identity token found in credentials source of account %s - could not set JWT cookie.', $account->getAccountIdentifier()), LogEnvironment::fromMethodName(__METHOD__));
            return;
        }

        $this->setJwtCookie($componentContext, $identityToken->asJwt());
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
     * @param ComponentContext $componentContext
     * @param string $jwt
     */
    private function setJwtCookie(ComponentContext $componentContext, string $jwt): void
    {
        $jwtCookie = new Cookie($this->options['cookie']['name'], $jwt, 0, null, null, '/', $this->options['cookie']['secure'], false, $this->options['cookie']['sameSite']);
        $componentContext->replaceHttpResponse($componentContext->getHttpResponse()->withAddedHeader('Set-Cookie', (string)$jwtCookie));
    }

    /**
     * @param ComponentContext $componentContext
     */
    private function removeJwtCookie(ComponentContext $componentContext): void
    {
        $emptyJwtCookie = new Cookie($this->options['cookie']['name'], '', 1, null, null, '/', $this->options['cookie']['secure'], false, $this->options['cookie']['sameSite']);
        $componentContext->replaceHttpResponse($componentContext->getHttpResponse()->withAddedHeader('Set-Cookie', (string)$emptyJwtCookie));
    }
}
