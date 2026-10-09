<?php
declare(strict_types=1);
namespace Flownative\OpenIdConnect\Client\Authentication;

use Flownative\OpenIdConnect\Client\IdentityToken;
use InvalidArgumentException;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Mvc\ActionRequest;
use Neos\Flow\Security\Exception\AccessDeniedException;
use Neos\Flow\Security\Exception\AuthenticationRequiredException;
use Neos\Flow\Security\Exception\InvalidAuthenticationStatusException;

/**
 * Signs in once with the identity token of a finished authorization, after which the Flow session keeps the login
 *
 * Unlike OpenIdConnectToken, this token is not sessionless: Flow keeps it authenticated in the session, tags the session with the
 * account and renews the session identifier after the login. It carries credentials only when the browser returns from the identity
 * provider.
 */
final class OpenIdConnectSessionToken extends AbstractOpenIdConnectToken
{
    #[Flow\Transient]
    protected bool $receivedRefreshToken = false;

    /**
     * Only a return from the identity provider can start a login, and only if nobody is signed in with this token yet
     *
     * A return while signed in is ignored, so that a link with the return parameters of somebody else's authorization can't sign
     * anybody out. To sign in with another account, the user signs out first. Without a login, only parameters which this
     * application signed lead to an authentication, so that made-up parameters don't even reach the provider.
     *
     * @throws InvalidAuthenticationStatusException
     */
    public function updateCredentials(ActionRequest $actionRequest): void
    {
        $httpRequest = $actionRequest->getHttpRequest();

        // The token is stored in the session, so nothing of the request may remain in it longer than needed
        $this->queryParameters = [];
        $this->cookies = [];
        $this->refreshToken = '';
        $this->receivedRefreshToken = false;
        $this->nonceCookieName = '';

        if ($this->isAuthenticated()) {
            return;
        }
        $queryParameters = $httpRequest->getQueryParams();
        if (!isset($queryParameters[self::OIDC_PARAMETER_NAME]) || !$this->isSignedByThisApplication($queryParameters[self::OIDC_PARAMETER_NAME])) {
            return;
        }
        $this->queryParameters = $queryParameters;
        $this->cookies = $httpRequest->getCookieParams();
        $this->setAuthenticationStatus(self::AUTHENTICATION_NEEDED);
    }

    /**
     * @return IdentityToken A syntactically valid but not verified (signature, claims) token
     * @throws AccessDeniedException
     * @throws AuthenticationRequiredException
     * @throws InvalidAuthenticationStatusException
     */
    public function extractIdentityTokenFromRequest(): IdentityToken
    {
        try {
            if (!$this->isReturnFromIdentityProvider()) {
                $this->setAuthenticationStatus(self::NO_CREDENTIALS_GIVEN);
                throw new AuthenticationRequiredException('The request does not return from the identity provider', 1791540871);
            }
            return $this->extractIdentityTokenFromFinishedAuthorization();
        } finally {
            $this->queryParameters = [];
            $this->cookies = [];
            // The session decides how long the login lasts, so a refresh token would only be a long-lived secret which nobody uses
            $this->receivedRefreshToken = $this->refreshToken !== '';
            $this->refreshToken = '';
        }
    }

    /**
     * Tells if the identity provider issued a refresh token with the finished authorization, which this token has discarded
     */
    public function hasReceivedRefreshToken(): bool
    {
        return $this->receivedRefreshToken;
    }

    private function isSignedByThisApplication(mixed $signedTokenArguments): bool
    {
        if (!is_string($signedTokenArguments)) {
            return false;
        }
        try {
            TokenArguments::fromSignedString($signedTokenArguments, $this->hashService);
            return true;
        } catch (InvalidArgumentException) {
            return false;
        }
    }
}
