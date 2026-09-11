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

use Flownative\OpenIdConnect\Client\Authentication\OpenIdConnectProvider;
use Flownative\OpenIdConnect\Client\Authentication\OpenIdConnectToken;
use Flownative\OpenIdConnect\Client\Tests\Unit\Fixtures\JwtFixture;
use Flownative\OpenIdConnect\Client\Tests\Unit\Fixtures\OpenIdConnectClientFixture;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\ServerRequest;
use Neos\Flow\Mvc\ActionRequest;
use Neos\Flow\Security\Account;
use Neos\Flow\Security\AccountRepository;
use Neos\Flow\Security\Authentication\TokenInterface;
use Neos\Flow\Security\Exception\UnsupportedAuthenticationTokenException;
use Neos\Flow\Security\Policy\PolicyService;
use Neos\Flow\Security\Policy\Role;
use Neos\Flow\Session\SessionInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use RuntimeException;

class OpenIdConnectProviderTest extends TestCase
{
    #[Test]
    public function getTokenClassNamesReturnsOpenIdConnectToken(): void
    {
        $provider = OpenIdConnectProvider::create('SomeProvider', []);

        static::assertSame([OpenIdConnectToken::class], $provider->getTokenClassNames());
    }

    #[Test]
    public function authenticateRejectsForeignTokens(): void
    {
        $provider = OpenIdConnectProvider::create('SomeProvider', ['roles' => [], 'serviceName' => 'test']);

        $this->expectException(UnsupportedAuthenticationTokenException::class);
        $this->expectExceptionCode(1559805996);
        $provider->authenticate($this->createStub(TokenInterface::class));
    }

    public static function incompleteOptions(): array
    {
        return [
            'no source for roles' => [['serviceName' => 'test'], 1559806095],
            'missing service name' => [['roles' => ['Some.Package:User']], 1561480057],
            'negative leeway' => [['serviceName' => 'test', 'roles' => [], 'leeway' => -1], 1789122177],
            'leeway is not a number' => [['serviceName' => 'test', 'roles' => [], 'leeway' => '60'], 1789122177],
        ];
    }

    #[Test]
    #[DataProvider('incompleteOptions')]
    public function authenticateRejectsIncompleteOptions(array $options, int $expectedExceptionCode): void
    {
        $provider = OpenIdConnectProvider::create('SomeProvider', $options);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionCode($expectedExceptionCode);
        $provider->authenticate(new OpenIdConnectToken());
    }

    #[Test]
    public function getServiceNameReturnsConfiguredServiceName(): void
    {
        static::assertSame('test', OpenIdConnectProvider::create('SomeProvider', ['serviceName' => 'test'])->getServiceName());
        static::assertSame('', OpenIdConnectProvider::create('SomeProvider', [])->getServiceName());
    }

    #[Test]
    public function authenticateAuthenticatesTransientAccountForValidToken(): void
    {
        $jwt = self::createJwt();
        $token = self::createTokenForBearerJwt($jwt);

        $this->createProvider(['roles' => ['Some.Package:User']])->authenticate($token);

        static::assertSame(TokenInterface::AUTHENTICATION_SUCCESSFUL, $token->getAuthenticationStatus());
        $account = $token->getAccount();
        static::assertSame('alice', $account->getAccountIdentifier());
        static::assertSame('SomeProvider', $account->getAuthenticationProviderName());
        static::assertSame($jwt, $account->getCredentialsSource());
        static::assertSame(['Some.Package:User'], array_keys($account->getRoles()));
    }

    #[Test]
    public function authenticateUsesConfiguredClaimAsAccountIdentifier(): void
    {
        $token = self::createTokenForBearerJwt(self::createJwt(['email' => 'alice@example.com']));

        $this->createProvider(['roles' => ['Some.Package:User'], 'accountIdentifierTokenValueName' => 'email'])->authenticate($token);

        static::assertSame('alice@example.com', $token->getAccount()->getAccountIdentifier());
    }

    public static function unusableAccountIdentifiers(): array
    {
        return [
            'missing' => [null],
            'empty' => [''],
            'not a string' => [['alice']],
        ];
    }

    #[Test]
    #[DataProvider('unusableAccountIdentifiers')]
    public function authenticateRejectsTokenWithoutUsableAccountIdentifier(mixed $subject): void
    {
        $token = self::createTokenForBearerJwt(self::createJwt(['sub' => $subject]));

        $this->createProvider(['roles' => ['Some.Package:User']])->authenticate($token);

        self::assertNotAuthenticated($token, TokenInterface::WRONG_CREDENTIALS);
    }

    #[Test]
    public function authenticateRejectsTokenWithInvalidSignature(): void
    {
        $token = self::createTokenForBearerJwt(self::createJwtWithInvalidSignature(['sub' => 'mallory']));

        $this->createProvider(['roles' => ['Some.Package:User']])->authenticate($token);

        self::assertNotAuthenticated($token, TokenInterface::WRONG_CREDENTIALS);
    }

    #[Test]
    public function authenticateDoesNotAuthenticateIfJsonWebKeySetCannotBeRetrieved(): void
    {
        $httpClient = $this->createStub(HttpClient::class);
        $httpClient->method('request')->willThrowException(new ConnectException('Connection refused', new Request('GET', OpenIdConnectClientFixture::JWKS_URI)));
        $token = self::createTokenForBearerJwt(self::createJwt());

        $this->createProvider(['roles' => ['Some.Package:User']], httpClient: $httpClient, jwks: [])->authenticate($token);

        self::assertNotAuthenticated($token, TokenInterface::AUTHENTICATION_NEEDED);
    }

    #[Test]
    public function authenticateAssignsRolesFromClaims(): void
    {
        $token = self::createTokenForBearerJwt(self::createJwt([
            'https://example.com/roles' => ['Some.Package:Editor', 'Unknown.Package:Role', ['Some.Package:Editor']],
        ]));
        $policyService = $this->createPolicyService(['Some.Package:Editor']);

        $this->createProvider(['rolesFromClaims' => ['https://example.com/roles']], policyService: $policyService)->authenticate($token);

        static::assertSame(['Some.Package:Editor'], array_keys($token->getAccount()->getRoles()));
    }

    #[Test]
    public function authenticateMapsRolesFromClaims(): void
    {
        $token = self::createTokenForBearerJwt(self::createJwt(['groups' => ['editors', 'guests']]));
        $options = ['rolesFromClaims' => [['name' => 'groups', 'mapping' => ['editors' => 'Some.Package:Editor']]]];

        $this->createProvider($options, policyService: $this->createPolicyService(['Some.Package:Editor']))->authenticate($token);

        static::assertSame(['Some.Package:Editor'], array_keys($token->getAccount()->getRoles()));
    }

    #[Test]
    public function authenticateAddsRolesFromExistingAccount(): void
    {
        $existingAccount = new Account();
        $existingAccount->addRole(new Role('Some.Package:Administrator'));
        $accountRepository = $this->createStub(AccountRepository::class);
        $accountRepository->method('findActiveByAccountIdentifierAndAuthenticationProviderName')->willReturnMap([['alice', 'SomeProvider', $existingAccount]]);
        $token = self::createTokenForBearerJwt(self::createJwt());

        $this->createProvider(['addRolesFromExistingAccount' => true], accountRepository: $accountRepository)->authenticate($token);

        static::assertSame(['Some.Package:Administrator'], array_keys($token->getAccount()->getRoles()));
    }

    public static function acceptedAudiences(): array
    {
        return [
            'client id by default' => [OpenIdConnectClientFixture::CLIENT_ID, null],
            'client id among multiple audiences' => [['https://other.example.com', OpenIdConnectClientFixture::CLIENT_ID], null],
            'configured audience' => ['https://app.example.com', 'https://app.example.com'],
            'configured audience among multiple audiences' => [['https://other.example.com', 'https://app.example.com'], 'https://app.example.com'],
            'one of several configured audiences' => ['https://api.example.com', ['https://app.example.com', 'https://api.example.com']],
        ];
    }

    #[Test]
    #[DataProvider('acceptedAudiences')]
    public function authenticateAcceptsTokenIssuedForExpectedAudience(string|array $audienceClaim, string|array|null $audienceOption): void
    {
        $token = self::createTokenForBearerJwt(self::createJwt(['aud' => $audienceClaim]));
        $options = ['roles' => ['Some.Package:User']];
        if ($audienceOption !== null) {
            $options['audience'] = $audienceOption;
        }

        $this->createProvider($options)->authenticate($token);

        static::assertSame(TokenInterface::AUTHENTICATION_SUCCESSFUL, $token->getAuthenticationStatus());
    }

    public static function rejectedAudiences(): array
    {
        return [
            'other audience than the client id' => ['https://other.example.com', null],
            'client id if another audience is configured' => [OpenIdConnectClientFixture::CLIENT_ID, 'https://app.example.com'],
            'no audience' => [null, null],
        ];
    }

    #[Test]
    #[DataProvider('rejectedAudiences')]
    public function authenticateRejectsTokenIssuedForOtherAudience(?string $audienceClaim, ?string $audienceOption): void
    {
        $token = self::createTokenForBearerJwt(self::createJwt(['aud' => $audienceClaim]));
        $options = ['roles' => ['Some.Package:User']];
        if ($audienceOption !== null) {
            $options['audience'] = $audienceOption;
        }

        $this->createProvider($options)->authenticate($token);

        self::assertNotAuthenticated($token, TokenInterface::WRONG_CREDENTIALS);
    }

    #[Test]
    public function authenticateThrowsExceptionIfNoAudienceIsConfigured(): void
    {
        $token = self::createTokenForBearerJwt(self::createJwt());

        $this->expectException(RuntimeException::class);
        $this->expectExceptionCode(1789122176);
        $this->createProvider(['roles' => ['Some.Package:User']], serviceOptions: ['clientId' => ''])->authenticate($token);
    }

    public static function rejectedIssuers(): array
    {
        return [
            'other issuer' => ['https://evil.example.com/'],
            'issuer without trailing slash' => ['https://id.example.com'],
            'no issuer' => [null],
        ];
    }

    #[Test]
    #[DataProvider('rejectedIssuers')]
    public function authenticateRejectsTokenFromOtherIssuer(?string $issuerClaim): void
    {
        $token = self::createTokenForBearerJwt(self::createJwt(['iss' => $issuerClaim]));

        $this->createProvider(['roles' => ['Some.Package:User']])->authenticate($token);

        self::assertNotAuthenticated($token, TokenInterface::WRONG_CREDENTIALS);
    }

    #[Test]
    public function authenticateThrowsExceptionIfIssuerIsUnknown(): void
    {
        $token = self::createTokenForBearerJwt(self::createJwt());

        $this->expectException(RuntimeException::class);
        $this->expectExceptionCode(1789122175);
        $this->createProvider(['roles' => ['Some.Package:User']], serviceOptions: ['issuer' => ''])->authenticate($token);
    }

    public static function tenantIssuers(): array
    {
        return [
            'matching tenant' => [['iss' => 'https://login.example.com/tenant-1/v2.0', 'tid' => 'tenant-1'], TokenInterface::AUTHENTICATION_SUCCESSFUL],
            'issuer of another tenant' => [['iss' => 'https://login.example.com/tenant-2/v2.0', 'tid' => 'tenant-1'], TokenInterface::WRONG_CREDENTIALS],
            'missing tenant identifier' => [['iss' => 'https://login.example.com/{tenantid}/v2.0'], TokenInterface::WRONG_CREDENTIALS],
            'invalid tenant identifier' => [['iss' => 'https://login.example.com/a/b/v2.0', 'tid' => 'a/b'], TokenInterface::WRONG_CREDENTIALS],
            'tenant identifier with line break' => [['iss' => "https://login.example.com/tenant-1\n/v2.0", 'tid' => "tenant-1\n"], TokenInterface::WRONG_CREDENTIALS],
        ];
    }

    #[Test]
    #[DataProvider('tenantIssuers')]
    public function authenticateResolvesTenantPlaceholderInIssuer(array $claims, int $expectedStatus): void
    {
        $token = self::createTokenForBearerJwt(self::createJwt($claims));

        $this->createProvider(['roles' => ['Some.Package:User']], serviceOptions: ['issuer' => 'https://login.example.com/{tenantid}/v2.0'])->authenticate($token);

        static::assertSame($expectedStatus, $token->getAuthenticationStatus());
    }

    public static function configuredIssuers(): array
    {
        return [
            'configured issuer instead of the service issuer' => [['iss' => 'https://sts.example.com/'], 'https://sts.example.com/', TokenInterface::AUTHENTICATION_SUCCESSFUL],
            'one of several configured issuers' => [['iss' => 'https://sts.example.com/tenant-1/', 'tid' => 'tenant-1'], [OpenIdConnectClientFixture::ISSUER, 'https://sts.example.com/{tenantid}/'], TokenInterface::AUTHENTICATION_SUCCESSFUL],
            'service issuer if another issuer is configured' => [[], 'https://sts.example.com/', TokenInterface::WRONG_CREDENTIALS],
        ];
    }

    #[Test]
    #[DataProvider('configuredIssuers')]
    public function authenticateUsesIssuerOptionOfProvider(array $claims, string|array $issuerOption, int $expectedStatus): void
    {
        $token = self::createTokenForBearerJwt(self::createJwt($claims));

        $this->createProvider(['roles' => ['Some.Package:User'], 'issuer' => $issuerOption])->authenticate($token);

        static::assertSame($expectedStatus, $token->getAuthenticationStatus());
    }

    #[Test]
    public function authenticateDoesNotAuthenticateIfClientCannotBeCreated(): void
    {
        $clientFactory = $this->createStub(OpenIdConnectClientFactory::class);
        $clientFactory->method('create')->willThrowException(new ConnectionException('OpenID Connect Client: Failed discovering options', 1554902567));
        $token = self::createTokenForBearerJwt(self::createJwt());

        $this->createProvider(['roles' => ['Some.Package:User']], clientFactory: $clientFactory)->authenticate($token);

        self::assertNotAuthenticated($token, TokenInterface::AUTHENTICATION_NEEDED);
    }

    #[Test]
    public function authenticateEscapesTokenValuesInLogMessages(): void
    {
        $messages = [];
        $logger = $this->createStub(LoggerInterface::class);
        $logger->method('notice')->willReturnCallback(static function (string $message) use (&$messages): void {
            $messages[] = $message;
        });
        $token = self::createTokenForBearerJwt(self::createJwt(['aud' => "other\nFAKE LOG LINE \u{202E}"]));

        $this->createProvider(['roles' => ['Some.Package:User']], logger: $logger)->authenticate($token);

        static::assertNotEmpty($messages);
        foreach ($messages as $message) {
            static::assertStringNotContainsString("\n", $message);
            static::assertStringNotContainsString("\u{202E}", $message);
        }
    }

    public static function timeClaims(): array
    {
        return [
            'expired within leeway' => [['exp' => time() - 30], TokenInterface::AUTHENTICATION_SUCCESSFUL],
            'expired beyond default leeway' => [['exp' => time() - 120], TokenInterface::AUTHENTICATION_NEEDED],
            'valid soon within leeway' => [['nbf' => time() + 30], TokenInterface::AUTHENTICATION_SUCCESSFUL],
            'issued soon within leeway' => [['iat' => time() + 30], TokenInterface::AUTHENTICATION_SUCCESSFUL],
            'not valid yet' => [['nbf' => time() + 600], TokenInterface::WRONG_CREDENTIALS],
            'issued in the future' => [['iat' => time() + 600], TokenInterface::WRONG_CREDENTIALS],
            'without expiration time' => [['exp' => null], TokenInterface::AUTHENTICATION_NEEDED],
        ];
    }

    #[Test]
    #[DataProvider('timeClaims')]
    public function authenticateChecksTimeClaimsWithLeeway(array $claims, int $expectedStatus): void
    {
        $token = self::createTokenForBearerJwt(self::createJwt($claims));

        $this->createProvider(['roles' => ['Some.Package:User']])->authenticate($token);

        static::assertSame($expectedStatus, $token->getAuthenticationStatus());
    }

    #[Test]
    public function authenticateUsesConfiguredLeeway(): void
    {
        $token = self::createTokenForBearerJwt(self::createJwt(['exp' => time() - 30]));

        $this->createProvider(['roles' => ['Some.Package:User'], 'leeway' => 0])->authenticate($token);

        self::assertNotAuthenticated($token, TokenInterface::AUTHENTICATION_NEEDED);
    }

    #[Test]
    public function authenticateRequiresAuthenticationForExpiredTokenWithoutRefreshToken(): void
    {
        $token = self::createTokenForBearerJwt(self::createJwt(['exp' => time() - 600]));

        $this->createProvider(['roles' => ['Some.Package:User']], session: $this->createSession(''))->authenticate($token);

        self::assertNotAuthenticated($token, TokenInterface::AUTHENTICATION_NEEDED);
    }

    #[Test]
    public function authenticateRefreshesExpiredTokenWithRefreshTokenFromSession(): void
    {
        $refreshedJwt = self::createJwt();
        $httpClient = $this->createMock(HttpClient::class);
        $httpClient->expects($this->once())
            ->method('request')
            ->with('POST', OpenIdConnectClientFixture::TOKEN_ENDPOINT, $this->callback(
                static fn (array $options): bool => $options['form_params']['grant_type'] === 'refresh_token'
                    && $options['form_params']['refresh_token'] === 'the-refresh-token'
                    && $options['form_params']['client_id'] === OpenIdConnectClientFixture::CLIENT_ID
            ))
            ->willReturn(new Response(200, [], json_encode(['id_token' => $refreshedJwt])));
        $token = self::createTokenForBearerJwt(self::createJwt(['exp' => time() - 600]));

        $this->createProvider(['roles' => ['Some.Package:User']], session: $this->createSession('the-refresh-token'), httpClient: $httpClient)->authenticate($token);

        static::assertSame(TokenInterface::AUTHENTICATION_SUCCESSFUL, $token->getAuthenticationStatus());
        static::assertSame($refreshedJwt, $token->getAccount()->getCredentialsSource());
    }

    #[Test]
    public function authenticateRejectsRefreshedTokenWithInvalidSignature(): void
    {
        $httpClient = $this->createStub(HttpClient::class);
        $httpClient->method('request')->willReturn(new Response(200, [], json_encode(['id_token' => self::createJwtWithInvalidSignature(['sub' => 'mallory'])])));
        $token = self::createTokenForBearerJwt(self::createJwt(['exp' => time() - 600]));

        $this->createProvider(['roles' => ['Some.Package:User']], session: $this->createSession('the-refresh-token'), httpClient: $httpClient)->authenticate($token);

        self::assertNotAuthenticated($token, TokenInterface::WRONG_CREDENTIALS);
    }

    #[Test]
    public function authenticateRejectsRefreshedTokenForOtherAudience(): void
    {
        $httpClient = $this->createStub(HttpClient::class);
        $httpClient->method('request')->willReturn(new Response(200, [], json_encode(['id_token' => self::createJwt(['aud' => 'https://other.example.com'])])));
        $token = self::createTokenForBearerJwt(self::createJwt(['exp' => time() - 600]));

        $this->createProvider(['roles' => ['Some.Package:User']], session: $this->createSession('the-refresh-token'), httpClient: $httpClient)->authenticate($token);

        self::assertNotAuthenticated($token, TokenInterface::WRONG_CREDENTIALS);
    }

    #[Test]
    public function authenticateDoesNotRefreshExpiredTokenIssuedForOtherAudience(): void
    {
        $httpClient = $this->createMock(HttpClient::class);
        $httpClient->expects($this->never())->method('request');
        $token = self::createTokenForBearerJwt(self::createJwt(['aud' => 'https://other.example.com', 'exp' => time() - 600]));

        $this->createProvider(['roles' => ['Some.Package:User']], session: $this->createSession('the-refresh-token'), httpClient: $httpClient)->authenticate($token);

        self::assertNotAuthenticated($token, TokenInterface::WRONG_CREDENTIALS);
    }

    #[Test]
    public function authenticateDoesNotStoreRefreshTokenOfRejectedToken(): void
    {
        $token = self::createTokenForBearerJwt(self::createJwt(['aud' => 'https://other.example.com']));
        OpenIdConnectClientFixture::inject($token, 'refreshToken', 'the-new-refresh-token');
        $session = $this->createMock(SessionInterface::class);
        $session->method('isStarted')->willReturn(true);
        $session->expects($this->never())->method('putData');

        $this->createProvider(['roles' => ['Some.Package:User']], session: $session)->authenticate($token);

        self::assertNotAuthenticated($token, TokenInterface::WRONG_CREDENTIALS);
    }

    #[Test]
    public function authenticateStoresRefreshTokenOfNewAuthorizationInSession(): void
    {
        $token = self::createTokenForBearerJwt(self::createJwt());
        OpenIdConnectClientFixture::inject($token, 'refreshToken', 'the-new-refresh-token');
        $session = $this->createMock(SessionInterface::class);
        $session->method('isStarted')->willReturn(true);
        $session->expects($this->once())->method('putData')->with('flownative_oidc_refresh', 'the-new-refresh-token');

        $this->createProvider(['roles' => ['Some.Package:User']], session: $session)->authenticate($token);

        static::assertSame(TokenInterface::AUTHENTICATION_SUCCESSFUL, $token->getAuthenticationStatus());
    }

    private function createProvider(
        array $options,
        ?SessionInterface $session = null,
        ?PolicyService $policyService = null,
        ?AccountRepository $accountRepository = null,
        ?HttpClient $httpClient = null,
        ?array $jwks = null,
        array $serviceOptions = [],
        ?LoggerInterface $logger = null,
        ?OpenIdConnectClientFactory $clientFactory = null
    ): OpenIdConnectProvider {
        $logger ??= $this->createStub(LoggerInterface::class);
        if ($clientFactory === null) {
            $client = OpenIdConnectClientFixture::createClient(
                $this->createStub(OAuthClient::class),
                OpenIdConnectClientFixture::createHashService(),
                $logger,
                $jwks ?? JwtFixture::createJwks(),
                $httpClient,
                $serviceOptions
            );
            $clientFactory = $this->createStub(OpenIdConnectClientFactory::class);
            $clientFactory->method('create')->willReturn($client);
        }

        $provider = OpenIdConnectProvider::create('SomeProvider', array_merge(['serviceName' => OpenIdConnectClientFixture::SERVICE_NAME], $options));
        OpenIdConnectClientFixture::inject($provider, 'logger', $logger);
        OpenIdConnectClientFixture::inject($provider, 'openIdConnectClientFactory', $clientFactory);
        OpenIdConnectClientFixture::inject($provider, 'session', $session ?? $this->createSession(''));
        OpenIdConnectClientFixture::inject($provider, 'policyService', $policyService ?? $this->createPolicyService(['Some.Package:User']));
        OpenIdConnectClientFixture::inject($provider, 'accountRepository', $accountRepository ?? $this->createStub(AccountRepository::class));
        return $provider;
    }

    private function createPolicyService(array $existingRoleIdentifiers): PolicyService
    {
        $policyService = $this->createStub(PolicyService::class);
        $policyService->method('hasRole')->willReturnCallback(static fn (string $roleIdentifier): bool => in_array($roleIdentifier, $existingRoleIdentifiers, true));
        $policyService->method('getRole')->willReturnCallback(static fn (string $roleIdentifier): Role => new Role($roleIdentifier));
        $policyService->method('getRoles')->willReturn([]);
        return $policyService;
    }

    private function createSession(string $storedRefreshToken): SessionInterface
    {
        $session = $this->createStub(SessionInterface::class);
        $session->method('isStarted')->willReturn(true);
        $session->method('getData')->willReturnMap([['flownative_oidc_refresh', $storedRefreshToken]]);
        return $session;
    }

    /**
     * Creates a signed JWT with valid default claims; claims set to null are left out
     */
    private static function createJwt(array $claims = []): string
    {
        $defaultClaims = [
            'iss' => OpenIdConnectClientFixture::ISSUER,
            'aud' => OpenIdConnectClientFixture::CLIENT_ID,
            'sub' => 'alice',
            'exp' => time() + 3600,
        ];
        return JwtFixture::createSignedJwt(array_filter(array_merge($defaultClaims, $claims), static fn (mixed $value): bool => $value !== null));
    }

    private static function createJwtWithInvalidSignature(array $claims): string
    {
        [$header, , $signature] = explode('.', self::createJwt());
        [, $forgedClaims] = explode('.', self::createJwt($claims));
        return $header . '.' . $forgedClaims . '.' . $signature;
    }

    private static function createTokenForBearerJwt(string $jwt): OpenIdConnectToken
    {
        $token = new OpenIdConnectToken();
        $token->updateCredentials(ActionRequest::fromHttpRequest(new ServerRequest('GET', 'https://www.example.com/', ['Authorization' => 'Bearer ' . $jwt])));
        return $token;
    }

    private static function assertNotAuthenticated(OpenIdConnectToken $token, int $expectedStatus): void
    {
        static::assertSame($expectedStatus, $token->getAuthenticationStatus());
        static::assertNull($token->getAccount());
    }
}
