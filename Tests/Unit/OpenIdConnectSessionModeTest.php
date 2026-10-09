<?php
declare(strict_types=1);

namespace Flownative\OpenIdConnect\Client;

/*
 * This file is part of the Flownative.OpenIdConnect.Client package.
 *
 * (c) Robert Lemke, Flownative GmbH - www.flownative.com
 *
 * This package is Open Source Software. For the full copyright and license
 * information, please view the LICENSE file which was distributed with this
 * source code.
 */

use Closure;
use Flownative\OAuth2\Client\Authorization;
use Flownative\OpenIdConnect\Client\Authentication\AccountResolverInterface;
use Flownative\OpenIdConnect\Client\Authentication\IdentityTokenOfLogin;
use Flownative\OpenIdConnect\Client\Authentication\Nonce;
use Flownative\OpenIdConnect\Client\Authentication\OpenIdConnectProvider;
use Flownative\OpenIdConnect\Client\Authentication\OpenIdConnectSessionToken;
use Flownative\OpenIdConnect\Client\Authentication\PersistedAccountResolver;
use Flownative\OpenIdConnect\Client\Authentication\TokenArguments;
use Flownative\OpenIdConnect\Client\Tests\Unit\Fixtures\JwtFixture;
use Flownative\OpenIdConnect\Client\Tests\Unit\Fixtures\OpenIdConnectClientFixture;
use GuzzleHttp\Psr7\ServerRequest;
use League\OAuth2\Client\Token\AccessToken;
use Neos\Flow\Annotations\Transient;
use Neos\Flow\Mvc\ActionRequest;
use Neos\Flow\ObjectManagement\ObjectManagerInterface;
use Neos\Flow\Persistence\PersistenceManagerInterface;
use Neos\Flow\Security\Account;
use Neos\Flow\Security\AccountRepository;
use Neos\Flow\Security\Authentication\TokenInterface;
use Neos\Flow\Security\Context as SecurityContext;
use Neos\Flow\Security\Cryptography\HashService;
use Neos\Flow\Security\Exception\AuthenticationRequiredException;
use Neos\Flow\Security\Policy\PolicyService;
use Neos\Flow\Session\SessionInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use ReflectionProperty;
use Psr\Log\LoggerInterface;
use RuntimeException;
use stdClass;

/**
 * The session token, the persisted account resolver and the provider in session mode
 */
class OpenIdConnectSessionModeTest extends TestCase
{
    private const string AUTHORIZATION_ID = 'oidc-test-4c1b7a0e-6f0c-4f7e-9d59-2d3a8c1f5e21';
    private const string AUTHORIZATION_HANDLE = '6f1c0b2d9a8e4f7c3b5a1d0e9f8c7b6a5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a';
    private const string RESOLVER_OBJECT_NAME = 'Acme\Security\AccountResolver';

    #[Test]
    public function updateCredentialsKeepsAuthenticationStatusOfRequestWithoutReturnParameters(): void
    {
        $token = new OpenIdConnectSessionToken();
        $token->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);

        $token->updateCredentials(self::createActionRequest(cookies: ['some' => 'cookie']));

        static::assertSame(TokenInterface::AUTHENTICATION_SUCCESSFUL, $token->getAuthenticationStatus());
    }

    #[Test]
    public function updateCredentialsRequiresAuthenticationForReturnFromIdentityProvider(): void
    {
        $hashService = OpenIdConnectClientFixture::createHashService();
        $token = new OpenIdConnectSessionToken();
        OpenIdConnectClientFixture::inject($token, 'hashService', $hashService);
        $token->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);

        $token->updateCredentials(self::createActionRequest(queryParameters: [OpenIdConnectSessionToken::OIDC_PARAMETER_NAME => (string)TokenArguments::fromArray([TokenArguments::SERVICE_NAME => OpenIdConnectClientFixture::SERVICE_NAME], $hashService)]));

        static::assertSame(TokenInterface::AUTHENTICATION_NEEDED, $token->getAuthenticationStatus());
    }

    #[Test]
    public function updateCredentialsIgnoresReturnFromIdentityProviderWhileSignedIn(): void
    {
        $hashService = OpenIdConnectClientFixture::createHashService();
        $token = new OpenIdConnectSessionToken();
        OpenIdConnectClientFixture::inject($token, 'hashService', $hashService);
        $token->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);

        $token->updateCredentials(self::createActionRequest(
            cookies: ['some' => 'cookie'],
            queryParameters: [OpenIdConnectSessionToken::OIDC_PARAMETER_NAME => (string)TokenArguments::fromArray([TokenArguments::SERVICE_NAME => OpenIdConnectClientFixture::SERVICE_NAME], $hashService)]
        ));

        static::assertSame(TokenInterface::AUTHENTICATION_SUCCESSFUL, $token->getAuthenticationStatus());
        static::assertSame([], (fn () => $this->cookies)->call($token));
        static::assertSame([], (fn () => $this->queryParameters)->call($token));
    }

    public static function argumentsNotSignedByThisApplication(): array
    {
        return [
            'made up' => ['arguments'],
            'not a string' => [['arguments']],
            'signed with another key' => [(string)TokenArguments::fromArray([TokenArguments::SERVICE_NAME => 'test'], self::createHashServiceWithKey('another-key'))],
        ];
    }

    #[Test]
    #[DataProvider('argumentsNotSignedByThisApplication')]
    public function updateCredentialsKeepsAuthenticationStatusForArgumentsNotSignedByThisApplication(string|array $arguments): void
    {
        $token = new OpenIdConnectSessionToken();
        OpenIdConnectClientFixture::inject($token, 'hashService', OpenIdConnectClientFixture::createHashService());

        $token->updateCredentials(self::createActionRequest(queryParameters: [OpenIdConnectSessionToken::OIDC_PARAMETER_NAME => $arguments]));

        static::assertSame(TokenInterface::NO_CREDENTIALS_GIVEN, $token->getAuthenticationStatus());
    }

    #[Test]
    public function valuesOfTheRequestAreNotStoredInTheSession(): void
    {
        foreach (['queryParameters', 'cookies', 'refreshToken', 'nonceCookieName', 'receivedRefreshToken'] as $propertyName) {
            $attributes = (new ReflectionProperty(OpenIdConnectSessionToken::class, $propertyName))->getAttributes(Transient::class);
            static::assertCount(1, $attributes, sprintf('Property "%s" is not transient', $propertyName));
        }
    }

    #[Test]
    public function extractIdentityTokenFromRequestDiscardsRefreshToken(): void
    {
        $hashService = OpenIdConnectClientFixture::createHashService();
        $nonce = Nonce::generate();
        $token = $this->createSessionToken($hashService, self::createSignedJwt(['nonce' => $nonce->value]), $nonce, 'the-refresh-token');

        $token->extractIdentityTokenFromRequest();

        static::assertSame('', $token->getRefreshToken());
        static::assertTrue($token->hasReceivedRefreshToken());
    }

    #[Test]
    public function updateCredentialsForgetsTheFinishedAuthorizationOfThePreviousRequest(): void
    {
        $token = new OpenIdConnectSessionToken();
        OpenIdConnectClientFixture::inject($token, 'nonceCookieName', 'flownative_oidc_nonce_0123456789abcdef');
        OpenIdConnectClientFixture::inject($token, 'refreshToken', 'the-refresh-token');

        $token->updateCredentials(self::createActionRequest());

        static::assertFalse($token->hasFinishedAuthorization());
        static::assertSame('', $token->getRefreshToken());
    }

    #[Test]
    public function extractIdentityTokenFromRequestRequiresReturnFromIdentityProvider(): void
    {
        $token = new OpenIdConnectSessionToken();
        $token->updateCredentials(self::createActionRequest());

        try {
            $token->extractIdentityTokenFromRequest();
            static::fail('No exception was thrown');
        } catch (AuthenticationRequiredException $exception) {
            static::assertSame(1791540871, $exception->getCode());
        }
        static::assertSame(TokenInterface::NO_CREDENTIALS_GIVEN, $token->getAuthenticationStatus());
    }

    #[Test]
    public function extractIdentityTokenFromRequestForgetsCookiesAndQueryParametersOfTheRequest(): void
    {
        $hashService = OpenIdConnectClientFixture::createHashService();
        $nonce = Nonce::generate();
        $token = $this->createSessionToken($hashService, self::createSignedJwt(['nonce' => $nonce->value]), $nonce);

        $token->extractIdentityTokenFromRequest();

        static::assertSame([], (fn () => $this->cookies)->call($token));
        static::assertSame([], (fn () => $this->queryParameters)->call($token));
        static::assertTrue($token->hasFinishedAuthorization());
    }

    #[Test]
    public function authenticateSignsInToTheResolvedPersistedAccount(): void
    {
        $account = self::createAccount('alice', 'Acme:Login');
        $resolver = $this->createMock(AccountResolverInterface::class);
        $resolver->expects($this->once())->method('resolve')
            ->with(static::callback(static fn (ValidatedIdentityToken $validatedIdentityToken): bool => $validatedIdentityToken->accountIdentifier === 'alice'), 'SomeProvider')
            ->willReturn($account);
        $persistenceManager = $this->createMock(PersistenceManagerInterface::class);
        $persistenceManager->method('isNewObject')->willReturn(false);
        $persistenceManager->expects($this->once())->method('allowObject')->with($account);
        $accountRepository = $this->createMock(AccountRepository::class);
        $accountRepository->expects($this->once())->method('update')->with($account);

        [$provider, $token] = $this->createProviderAndTokenForReturn(resolver: $resolver, persistenceManager: $persistenceManager, accountRepository: $accountRepository);
        $provider->authenticate($token);

        static::assertSame(TokenInterface::AUTHENTICATION_SUCCESSFUL, $token->getAuthenticationStatus());
        static::assertSame($account, $token->getAccount());
        static::assertNotNull($account->getLastSuccessfulAuthenticationDate());
    }

    #[Test]
    public function authenticateWarnsAboutRefreshTokenInSessionMode(): void
    {
        $resolver = $this->createStub(AccountResolverInterface::class);
        $resolver->method('resolve')->willReturn(self::createAccount('alice', 'SomeProvider'));
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects($this->once())->method('warning')->with(static::stringContains('requestRefreshToken'));

        [$provider, $token] = $this->createProviderAndTokenForReturn(resolver: $resolver, refreshToken: 'the-refresh-token');
        OpenIdConnectClientFixture::inject($provider, 'logger', $logger);
        $provider->authenticate($token);

        static::assertSame(TokenInterface::AUTHENTICATION_SUCCESSFUL, $token->getAuthenticationStatus());
    }

    #[Test]
    public function authenticateRemovesRefreshTokenOfAnEarlierLoginInJwtModeFromTheSession(): void
    {
        $resolver = $this->createStub(AccountResolverInterface::class);
        $resolver->method('resolve')->willReturn(self::createAccount('alice', 'SomeProvider'));
        $session = $this->createMock(SessionInterface::class);
        $session->method('isStarted')->willReturn(true);
        $session->expects($this->once())->method('putData')->with('flownative_oidc_refresh:SomeProvider', null);

        [$provider, $token] = $this->createProviderAndTokenForReturn(resolver: $resolver);
        OpenIdConnectClientFixture::inject($provider, 'session', $session);
        $provider->authenticate($token);
    }

    #[Test]
    public function authenticateRemembersTheIdentityTokenForSigningOut(): void
    {
        $resolver = $this->createStub(AccountResolverInterface::class);
        $resolver->method('resolve')->willReturn(self::createAccount('alice', 'SomeProvider'));
        $session = $this->createMock(SessionInterface::class);
        $session->expects($this->once())->method('putData')->with('flownative_oidc_identity_token:SomeProvider', static::callback(static fn (string $jwt): bool => (IdentityToken::fromJwt($jwt)->values['sub'] ?? null) === 'alice'));

        [$provider, $token] = $this->createProviderAndTokenForReturn(resolver: $resolver, identityTokenOfLogin: $this->createIdentityTokenOfLogin($session));
        $provider->authenticate($token);
    }

    #[Test]
    public function authenticateDoesNotRememberIdentityTokenOfRejectedIdentity(): void
    {
        $resolver = $this->createStub(AccountResolverInterface::class);
        $resolver->method('resolve')->willReturn(null);
        $session = $this->createMock(SessionInterface::class);
        $session->expects($this->never())->method('putData');

        [$provider, $token] = $this->createProviderAndTokenForReturn(resolver: $resolver, identityTokenOfLogin: $this->createIdentityTokenOfLogin($session));
        $provider->authenticate($token);
    }

    #[Test]
    public function authenticatePassesLookupProviderNameToTheResolver(): void
    {
        $resolver = $this->createMock(AccountResolverInterface::class);
        $resolver->expects($this->once())->method('resolve')->with(static::anything(), 'Acme:Login')->willReturn(self::createAccount('alice', 'Acme:Login'));

        [$provider, $token] = $this->createProviderAndTokenForReturn(['lookupProviderName' => 'Acme:Login'], resolver: $resolver);
        $provider->authenticate($token);

        static::assertSame(TokenInterface::AUTHENTICATION_SUCCESSFUL, $token->getAuthenticationStatus());
    }

    #[Test]
    public function authenticateRejectsIdentityWhichTheResolverDoesNotAdmit(): void
    {
        $resolver = $this->createStub(AccountResolverInterface::class);
        $resolver->method('resolve')->willReturn(null);

        [$provider, $token] = $this->createProviderAndTokenForReturn(resolver: $resolver);
        $provider->authenticate($token);

        static::assertSame(TokenInterface::WRONG_CREDENTIALS, $token->getAuthenticationStatus());
        static::assertNull($token->getAccount());
    }

    public static function rejectedIdentityTokens(): array
    {
        return [
            'expired' => [['exp' => time() - 3600]],
            'other audience' => [['aud' => 'other-client']],
            'other authorized party' => [['azp' => 'other-client']],
        ];
    }

    #[Test]
    #[DataProvider('rejectedIdentityTokens')]
    public function authenticateRejectsIdentityTokenWhichFailsACheckWithoutAskingTheResolver(array $claims): void
    {
        $resolver = $this->createMock(AccountResolverInterface::class);
        $resolver->expects($this->never())->method('resolve');

        [$provider, $token] = $this->createProviderAndTokenForReturn(claims: $claims, resolver: $resolver);
        $provider->authenticate($token);

        static::assertSame(TokenInterface::WRONG_CREDENTIALS, $token->getAuthenticationStatus());
    }

    #[Test]
    public function authenticateDoesNotUpdateAccountWhichIsNotPersisted(): void
    {
        $resolver = $this->createStub(AccountResolverInterface::class);
        $resolver->method('resolve')->willReturn(self::createAccount('alice', 'SomeProvider'));
        $persistenceManager = $this->createMock(PersistenceManagerInterface::class);
        $persistenceManager->method('isNewObject')->willReturn(true);
        $persistenceManager->expects($this->never())->method('allowObject');

        [$provider, $token] = $this->createProviderAndTokenForReturn(resolver: $resolver, persistenceManager: $persistenceManager);
        $provider->authenticate($token);

        static::assertSame(TokenInterface::AUTHENTICATION_SUCCESSFUL, $token->getAuthenticationStatus());
    }

    #[Test]
    public function authenticateLeavesTokenWithoutReturnParametersUnauthenticated(): void
    {
        $resolver = $this->createMock(AccountResolverInterface::class);
        $resolver->expects($this->never())->method('resolve');
        [$provider] = $this->createProviderAndTokenForReturn(resolver: $resolver);
        $token = new OpenIdConnectSessionToken();
        $token->updateCredentials(self::createActionRequest());

        $provider->authenticate($token);

        static::assertSame(TokenInterface::NO_CREDENTIALS_GIVEN, $token->getAuthenticationStatus());
    }

    public static function optionsNotAllowedInSessionMode(): array
    {
        return [
            'fixed roles' => [['roles' => ['Some.Package:User']], 1791540872],
            'roles from claims' => [['rolesFromClaims' => ['roles']], 1791540872],
            'roles from existing account' => [['addRolesFromExistingAccount' => true], 1791540872],
            'no account resolver' => [['accountResolver' => null], 1791540873],
            'empty lookup provider name' => [['lookupProviderName' => ''], 1791540874],
        ];
    }

    #[Test]
    #[DataProvider('optionsNotAllowedInSessionMode')]
    public function authenticateRejectsOptionsNotAllowedInSessionMode(array $options, int $expectedExceptionCode): void
    {
        [$provider, $token] = $this->createProviderAndTokenForReturn($options);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionCode($expectedExceptionCode);
        $provider->authenticate($token);
    }

    #[Test]
    public function authenticateRejectsAccountResolverWhichDoesNotImplementTheInterface(): void
    {
        $objectManager = $this->createStub(ObjectManagerInterface::class);
        $objectManager->method('get')->willReturn(new stdClass());
        [$provider, $token] = $this->createProviderAndTokenForReturn(objectManager: $objectManager);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionCode(1791540875);
        $provider->authenticate($token);
    }

    public static function persistedAccounts(): array
    {
        return [
            'same identifier' => ['alice', true],
            'identifier differing in case' => ['Alice', false],
            'identifier with trailing space' => ['alice ', false],
        ];
    }

    #[Test]
    #[DataProvider('persistedAccounts')]
    public function persistedAccountResolverOnlyReturnsAccountWithExactlyTheSameIdentifier(string $foundAccountIdentifier, bool $expectedToBeReturned): void
    {
        $account = self::createAccount($foundAccountIdentifier, 'Acme:Login');
        $accountRepository = $this->createMock(AccountRepository::class);
        $accountRepository->expects($this->once())->method('findActiveByAccountIdentifierAndAuthenticationProviderName')->with('alice', 'Acme:Login')->willReturn($account);
        $resolver = new PersistedAccountResolver();
        OpenIdConnectClientFixture::inject($resolver, 'accountRepository', $accountRepository);

        $resolvedAccount = $resolver->resolve(new ValidatedIdentityToken(IdentityToken::fromJwt(self::createSignedJwt()), 'alice'), 'Acme:Login');

        static::assertSame($expectedToBeReturned ? $account : null, $resolvedAccount);
    }

    #[Test]
    public function persistedAccountResolverReturnsNullIfNoActiveAccountExists(): void
    {
        $accountRepository = $this->createStub(AccountRepository::class);
        $accountRepository->method('findActiveByAccountIdentifierAndAuthenticationProviderName')->willReturn(null);
        $resolver = new PersistedAccountResolver();
        OpenIdConnectClientFixture::inject($resolver, 'accountRepository', $accountRepository);

        static::assertNull($resolver->resolve(new ValidatedIdentityToken(IdentityToken::fromJwt(self::createSignedJwt()), 'alice'), 'SomeProvider'));
    }

    /**
     * @return array{0: OpenIdConnectProvider, 1: OpenIdConnectSessionToken}
     */
    private function createProviderAndTokenForReturn(
        array $options = [],
        array $claims = [],
        ?AccountResolverInterface $resolver = null,
        ?PersistenceManagerInterface $persistenceManager = null,
        ?AccountRepository $accountRepository = null,
        ?ObjectManagerInterface $objectManager = null,
        string $refreshToken = '',
        ?IdentityTokenOfLogin $identityTokenOfLogin = null,
    ): array {
        $hashService = OpenIdConnectClientFixture::createHashService();
        $nonce = Nonce::generate();
        $token = $this->createSessionToken($hashService, self::createSignedJwt(array_merge(['nonce' => $nonce->value], $claims)), $nonce, $refreshToken);

        $clientFactory = $this->createStub(OpenIdConnectClientFactory::class);
        $clientFactory->method('create')->willReturn(OpenIdConnectClientFixture::createClient($this->createStub(OAuthClient::class), $hashService, $this->createStub(LoggerInterface::class), JwtFixture::createJwks()));
        if ($objectManager === null) {
            $objectManager = $this->createStub(ObjectManagerInterface::class);
            $objectManager->method('get')->willReturnCallback(fn (string $objectName): object => $objectName === self::RESOLVER_OBJECT_NAME ? ($resolver ?? $this->createStub(AccountResolverInterface::class)) : throw new RuntimeException('Unknown object ' . $objectName));
        }
        $securityContext = $this->createStub(SecurityContext::class);
        $securityContext->method('withoutAuthorizationChecks')->willReturnCallback(static fn (Closure $callback): mixed => $callback());
        $policyService = $this->createStub(PolicyService::class);
        $policyService->method('getRoles')->willReturn([]);

        $options = array_filter(array_merge(['serviceName' => OpenIdConnectClientFixture::SERVICE_NAME, 'accountResolver' => self::RESOLVER_OBJECT_NAME], $options), static fn (mixed $value): bool => $value !== null);
        $provider = OpenIdConnectProvider::create('SomeProvider', $options);
        OpenIdConnectClientFixture::inject($provider, 'logger', $this->createStub(LoggerInterface::class));
        OpenIdConnectClientFixture::inject($provider, 'openIdConnectClientFactory', $clientFactory);
        OpenIdConnectClientFixture::inject($provider, 'identityTokenValidator', new IdentityTokenValidator());
        OpenIdConnectClientFixture::inject($provider, 'objectManager', $objectManager);
        OpenIdConnectClientFixture::inject($provider, 'persistenceManager', $persistenceManager ?? $this->createStub(PersistenceManagerInterface::class));
        OpenIdConnectClientFixture::inject($provider, 'accountRepository', $accountRepository ?? $this->createStub(AccountRepository::class));
        OpenIdConnectClientFixture::inject($provider, 'securityContext', $securityContext);
        OpenIdConnectClientFixture::inject($provider, 'session', $this->createStub(SessionInterface::class));
        OpenIdConnectClientFixture::inject($provider, 'policyService', $policyService);
        OpenIdConnectClientFixture::inject($provider, 'identityTokenOfLogin', $identityTokenOfLogin ?? $this->createIdentityTokenOfLogin($this->createStub(SessionInterface::class)));
        return [$provider, $token];
    }

    /**
     * Returns a token for a request which returns from the identity provider with the given identity token
     */
    private function createSessionToken(HashService $hashService, string $identityTokenJwt, Nonce $nonce, string $refreshToken = ''): OpenIdConnectSessionToken
    {
        $authorization = new Authorization(self::AUTHORIZATION_ID, 'oidc', OpenIdConnectClientFixture::CLIENT_ID, Authorization::GRANT_AUTHORIZATION_CODE, 'openid');
        $authorization->setSerializedAccessToken(json_encode(new AccessToken(array_filter(['access_token' => 'the-access-token', 'refresh_token' => $refreshToken, 'id_token' => $identityTokenJwt])), JSON_THROW_ON_ERROR));
        $oAuthClient = $this->createStub(OAuthClient::class);
        $oAuthClient->method('claimAuthorization')->willReturn($authorization);
        $clientFactory = $this->createStub(OpenIdConnectClientFactory::class);
        $clientFactory->method('create')->willReturn(OpenIdConnectClientFixture::createClient($oAuthClient, $hashService, $this->createStub(LoggerInterface::class)));

        $token = new OpenIdConnectSessionToken();
        OpenIdConnectClientFixture::inject($token, 'openIdConnectClientFactory', $clientFactory);
        OpenIdConnectClientFixture::inject($token, 'hashService', $hashService);

        $cookie = $nonce->createCookie(CookieSettings::fromMiddlewareSettings([]));
        $tokenArguments = TokenArguments::fromArray([TokenArguments::SERVICE_NAME => OpenIdConnectClientFixture::SERVICE_NAME, TokenArguments::NONCE => $nonce->value], $hashService);
        $token->updateCredentials(self::createActionRequest(
            cookies: [$cookie->getName() => $cookie->getValue()],
            queryParameters: [
                OpenIdConnectSessionToken::OIDC_PARAMETER_NAME => (string)$tokenArguments,
                OAuthClient::generateAuthorizationIdQueryParameterName(OAuthClient::SERVICE_TYPE) => self::AUTHORIZATION_HANDLE,
            ]
        ));
        return $token;
    }

    private function createIdentityTokenOfLogin(SessionInterface $session): IdentityTokenOfLogin
    {
        $identityTokenOfLogin = new IdentityTokenOfLogin();
        OpenIdConnectClientFixture::inject($identityTokenOfLogin, 'session', $session);
        OpenIdConnectClientFixture::inject($identityTokenOfLogin, 'securityContext', $this->createStub(SecurityContext::class));
        return $identityTokenOfLogin;
    }

    private static function createHashServiceWithKey(string $encryptionKey): HashService
    {
        $hashService = new HashService();
        OpenIdConnectClientFixture::inject($hashService, 'encryptionKey', $encryptionKey);
        return $hashService;
    }

    private static function createAccount(string $accountIdentifier, string $authenticationProviderName): Account
    {
        $account = new Account();
        $account->setAccountIdentifier($accountIdentifier);
        $account->setAuthenticationProviderName($authenticationProviderName);
        return $account;
    }

    private static function createSignedJwt(array $claims = []): string
    {
        $defaultClaims = [
            'iss' => OpenIdConnectClientFixture::ISSUER,
            'aud' => OpenIdConnectClientFixture::CLIENT_ID,
            'sub' => 'alice',
            'exp' => time() + 3600,
        ];
        return JwtFixture::createSignedJwt(array_merge($defaultClaims, $claims));
    }

    private static function createActionRequest(array $cookies = [], array $queryParameters = []): ActionRequest
    {
        return ActionRequest::fromHttpRequest((new ServerRequest('GET', 'https://www.example.com/'))->withCookieParams($cookies)->withQueryParams($queryParameters));
    }
}
