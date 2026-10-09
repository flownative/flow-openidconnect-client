<?php
declare(strict_types=1);
namespace Flownative\OpenIdConnect\Client\Authentication;

use Flownative\OpenIdConnect\Client\IdentityToken;
use InvalidArgumentException;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Security\Context as SecurityContext;
use Neos\Flow\Session\SessionInterface;

/**
 * Knows the identity token of the current login, which the identity provider expects as "id_token_hint" when the user signs out
 *
 * In the JWT mode, the authenticated account carries the identity token. In the session mode, the provider keeps it in the session,
 * which Flow destroys on logout. So the token must be taken before the application ends the login.
 */
#[Flow\Scope('singleton')]
final class IdentityTokenOfLogin
{
    private const string SESSION_KEY_PREFIX = 'flownative_oidc_identity_token:';

    #[Flow\Inject]
    protected SecurityContext $securityContext;

    #[Flow\Inject]
    protected SessionInterface $session;

    /**
     * Returns the identity token of the login with the given authentication provider, or null if there is none
     */
    public function find(string $authenticationProviderName): ?IdentityToken
    {
        foreach ($this->securityContext->getAuthenticationTokensOfType(AbstractOpenIdConnectToken::class) as $token) {
            if ($token->getAuthenticationProviderName() !== $authenticationProviderName || !$token->isAuthenticated()) {
                continue;
            }
            $jwt = $token instanceof OpenIdConnectToken ? $token->getAccount()?->getCredentialsSource() : $this->findInSession($authenticationProviderName);
            try {
                return is_string($jwt) ? IdentityToken::fromJwt($jwt) : null;
            } catch (InvalidArgumentException) {
                return null;
            }
        }
        return null;
    }

    /**
     * Keeps the identity token of a login in the session mode, where the account doesn't carry it
     */
    public function rememberInSession(string $authenticationProviderName, IdentityToken $identityToken): void
    {
        if (!$this->session->isStarted()) {
            $this->session->start();
        }
        $this->session->putData(self::SESSION_KEY_PREFIX . $authenticationProviderName, $identityToken->asJwt());
    }

    private function findInSession(string $authenticationProviderName): mixed
    {
        if ($this->session->canBeResumed()) {
            $this->session->resume();
        }
        return $this->session->isStarted() ? $this->session->getData(self::SESSION_KEY_PREFIX . $authenticationProviderName) : null;
    }
}
