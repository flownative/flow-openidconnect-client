<?php
declare(strict_types=1);
namespace Flownative\OpenIdConnect\Client\Http;

use Flownative\OpenIdConnect\Client\Authentication\OpenIdConnectToken;
use Flownative\OpenIdConnect\Client\AuthenticationException;
use Flownative\OpenIdConnect\Client\IdentityToken;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Http\Component\ComponentContext;
use Neos\Flow\Http\Component\ComponentInterface;
use Neos\Flow\Http\Cookie;
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

    public function __construct(array $options = null)
    {
        $this->options = $options;
    }

    /**
     * @param ComponentContext $componentContext
     */
    public function handle(ComponentContext $componentContext): void
    {
        if (!$this->securityContext->isInitialized() && !$this->securityContext->canBeInitialized()) {
            $this->logger->debug(sprintf('OpenID Connect Client: (%s) Cannot send JWT cookie because the security context could not be initialized.', get_class($this)));
            return;
        }
        if (!$this->isOpenIdConnectAuthentication()) {
            return;
        }
        $account = $this->securityContext->getAccountByAuthenticationProviderName($this->options['authenticationProviderName']);
        if ($account === null) {
            $this->logger->info(sprintf('OpenID Connect Client: (%s) No Flow account found for %s, removing JWT cookie.', get_class($this), $this->options['authenticationProviderName']));
            $this->removeJwtCookie($componentContext);
            return;
        }

        $identityToken = $account->getCredentialsSource();
        if (!$identityToken instanceof IdentityToken) {
            $this->logger->error(sprintf('OpenID Connect Client: (%s) No identity token found in credentials source of account %s - could not set JWT cookie.', get_class($this), $account->getAccountIdentifier()));
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
        $jwtCookie = new Cookie($this->options['cookieName'], $jwt, 0, null, null, '/', $this->options['secureCookie'], false);
        $componentContext->replaceHttpResponse($componentContext->getHttpResponse()->withAddedHeader('Set-Cookie', (string)$jwtCookie));
    }

    /**
     * @param ComponentContext $componentContext
     */
    private function removeJwtCookie(ComponentContext $componentContext): void
    {
        $emptyJwtCookie = new Cookie($this->options['cookieName'], '', 1, null, null, '/', $this->options['secureCookie'], false);
        $componentContext->replaceHttpResponse($componentContext->getHttpResponse()->withAddedHeader('Set-Cookie', (string)$emptyJwtCookie));
    }
}
