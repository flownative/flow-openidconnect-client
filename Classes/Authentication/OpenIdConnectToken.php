<?php
declare(strict_types = 1);
namespace Flownative\OpenIdConnect\Client\Authentication;

use Flownative\OAuth2\Client\OAuthClient;
use Flownative\OpenIdConnect\Client\IdentityToken;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Mvc\ActionRequest;
use Neos\Flow\Security\Authentication\Token\AbstractToken;
use Neos\Flow\Security\Authentication\Token\SessionlessTokenInterface;
use Neos\Flow\Security\Exception\InvalidAuthenticationStatusException;
use Psr\Log\LoggerInterface;

final class OpenIdConnectToken extends AbstractToken implements SessionlessTokenInterface
{
    public const OID_PARAMETER_NAME = 'flownative_oidc';

    // FIXME: Hardcoded cookie name
    public const JWT_COOKIE_NAME = 'flownative_jwt';

    /**
     * @var string
     */
    private $stateIdentifier;

    /**
     * @var string
     */
    private $serviceName;

    /**
     * @var IdentityToken
     */
    private $identityToken;

    /**
     * @Flow\Inject
     * @var LoggerInterface
     */
    protected $logger;

    /**
     * @param ActionRequest $actionRequest
     * @throws InvalidAuthenticationStatusException
     */
    public function updateCredentials(ActionRequest $actionRequest): void
    {
        $request = $actionRequest->getHttpRequest();

        $jwt = $request->getCookieParams()[self::JWT_COOKIE_NAME] ?? null;
        if (!is_string($jwt) || $jwt === '') {
            return;
        }

        try {
            $this->identityToken = IdentityToken::fromJwt($jwt);
        } catch (\InvalidArgumentException $exception) {
            $this->setAuthenticationStatus(self::WRONG_CREDENTIALS);
            $this->logger->error(sprintf($exception->getMessage()));
            return;
        }

        $this->setAuthenticationStatus(self::AUTHENTICATION_NEEDED);

        $queryParameters = $actionRequest->getHttpRequest()->getQueryParams();
        if (!isset($queryParameters[self::OID_PARAMETER_NAME])) {
            return;
        }

        try {
            $tokenArguments = TokenArguments::fromSignedString($queryParameters[self::OID_PARAMETER_NAME]);
        } catch (\InvalidArgumentException $exception) {
            $this->setAuthenticationStatus(self::WRONG_CREDENTIALS);
            $this->logger->error(sprintf($exception->getMessage()));
            return;
        }

        $this->logger->info(sprintf('OpenID Connect: Received request with %s parameter', self::OID_PARAMETER_NAME));

        $this->stateIdentifier = $queryParameters[OAuthClient::STATE_QUERY_PARAMETER_NAME] ?? null;
        $this->serviceName = $tokenArguments[TokenArguments::SERVICE_NAME];
    }

    /**
     * @return bool
     */
    public function isEmpty(): bool
    {
        return !($this->serviceName !== null && $this->stateIdentifier !== null);
    }

    /**
     * @return string
     */
    public function authorizationIdentifier(): string
    {
        return $this->stateIdentifier;
    }

    /**
     * @return string
     */
    public function getServiceName(): string
    {
        return $this->serviceName;
    }

    /**
     * @return IdentityToken|null
     */
    public function getIdentityToken(): ?IdentityToken
    {
        return $this->identityToken;
    }

    /**
     * @return string
     */
    public function __toString()
    {
        return (string)$this->identityToken;
    }
}
