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
        $jwt = JwtFixture::createSignedJwt(['sub' => 'alice', 'exp' => time() + 3600]);
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
        $token = self::createTokenForBearerJwt(JwtFixture::createSignedJwt(['sub' => 'alice', 'email' => 'alice@example.com', 'exp' => time() + 3600]));

        $this->createProvider(['roles' => ['Some.Package:User'], 'accountIdentifierTokenValueName' => 'email'])->authenticate($token);

        static::assertSame('alice@example.com', $token->getAccount()->getAccountIdentifier());
    }

    #[Test]
    public function authenticateRejectsTokenWithoutAccountIdentifierClaim(): void
    {
        $token = self::createTokenForBearerJwt(JwtFixture::createSignedJwt(['exp' => time() + 3600]));

        $this->expectException(AuthenticationException::class);
        $this->expectExceptionCode(1560267246);
        $this->createProvider(['roles' => ['Some.Package:User']])->authenticate($token);
    }

    #[Test]
    public function authenticateDoesNotAuthenticateTokenWithInvalidSignature(): void
    {
        [$header, , $signature] = explode('.', JwtFixture::createSignedJwt(['sub' => 'alice', 'exp' => time() + 3600]));
        $forgedClaims = rtrim(strtr(base64_encode(json_encode(['sub' => 'mallory', 'exp' => time() + 3600])), '+/', '-_'), '=');
        $token = self::createTokenForBearerJwt($header . '.' . $forgedClaims . '.' . $signature);

        $this->createProvider(['roles' => ['Some.Package:User']])->authenticate($token);

        static::assertSame(TokenInterface::AUTHENTICATION_NEEDED, $token->getAuthenticationStatus());
        static::assertNull($token->getAccount());
    }

    #[Test]
    public function authenticateAssignsRolesFromClaims(): void
    {
        $token = self::createTokenForBearerJwt(JwtFixture::createSignedJwt([
            'sub' => 'alice',
            'exp' => time() + 3600,
            'https://example.com/roles' => ['Some.Package:Editor', 'Unknown.Package:Role'],
        ]));
        $policyService = $this->createPolicyService(['Some.Package:Editor']);

        $this->createProvider(['rolesFromClaims' => ['https://example.com/roles']], policyService: $policyService)->authenticate($token);

        static::assertSame(['Some.Package:Editor'], array_keys($token->getAccount()->getRoles()));
    }

    #[Test]
    public function authenticateMapsRolesFromClaims(): void
    {
        $token = self::createTokenForBearerJwt(JwtFixture::createSignedJwt([
            'sub' => 'alice',
            'exp' => time() + 3600,
            'groups' => ['editors', 'guests'],
        ]));
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
        $token = self::createTokenForBearerJwt(JwtFixture::createSignedJwt(['sub' => 'alice', 'exp' => time() + 3600]));

        $this->createProvider(['addRolesFromExistingAccount' => true], accountRepository: $accountRepository)->authenticate($token);

        static::assertSame(['Some.Package:Administrator'], array_keys($token->getAccount()->getRoles()));
    }

    public static function matchingAudiences(): array
    {
        return [
            'single audience' => ['https://app.example.com'],
            'one of multiple audiences' => [['https://other.example.com', 'https://app.example.com']],
        ];
    }

    #[Test]
    #[DataProvider('matchingAudiences')]
    public function authenticateAcceptsTokenIssuedForConfiguredAudience(string|array $audienceClaim): void
    {
        $token = self::createTokenForBearerJwt(JwtFixture::createSignedJwt(['sub' => 'alice', 'aud' => $audienceClaim, 'exp' => time() + 3600]));

        $this->createProvider(['roles' => ['Some.Package:User'], 'audience' => 'https://app.example.com'])->authenticate($token);

        static::assertSame(TokenInterface::AUTHENTICATION_SUCCESSFUL, $token->getAuthenticationStatus());
    }

    #[Test]
    public function authenticateRejectsTokenIssuedForOtherAudience(): void
    {
        $token = self::createTokenForBearerJwt(JwtFixture::createSignedJwt(['sub' => 'alice', 'aud' => 'https://other.example.com', 'exp' => time() + 3600]));

        $this->expectException(AuthenticationException::class);
        $this->expectExceptionCode(1616568739);
        $this->createProvider(['roles' => ['Some.Package:User'], 'audience' => 'https://app.example.com'])->authenticate($token);
    }

    #[Test]
    public function authenticateRequiresAuthenticationForExpiredTokenWithoutRefreshToken(): void
    {
        $token = self::createTokenForBearerJwt(JwtFixture::createSignedJwt(['sub' => 'alice', 'exp' => time() - 60]));

        $this->createProvider(['roles' => ['Some.Package:User']], session: $this->createSession(''))->authenticate($token);

        static::assertSame(TokenInterface::AUTHENTICATION_NEEDED, $token->getAuthenticationStatus());
        static::assertNull($token->getAccount());
    }

    #[Test]
    public function authenticateRefreshesExpiredTokenWithRefreshTokenFromSession(): void
    {
        $expiredJwt = JwtFixture::createSignedJwt(['sub' => 'alice', 'exp' => time() - 60]);
        $refreshedJwt = JwtFixture::createSignedJwt(['sub' => 'alice', 'exp' => time() + 3600]);
        $httpClient = $this->createMock(HttpClient::class);
        $httpClient->expects($this->once())
            ->method('request')
            ->with('POST', OpenIdConnectClientFixture::TOKEN_ENDPOINT, $this->callback(
                static fn (array $options): bool => $options['form_params']['grant_type'] === 'refresh_token'
                    && $options['form_params']['refresh_token'] === 'the-refresh-token'
                    && $options['form_params']['client_id'] === OpenIdConnectClientFixture::CLIENT_ID
            ))
            ->willReturn(new Response(200, [], json_encode(['id_token' => $refreshedJwt])));
        $token = self::createTokenForBearerJwt($expiredJwt);

        $this->createProvider(['roles' => ['Some.Package:User']], session: $this->createSession('the-refresh-token'), httpClient: $httpClient)->authenticate($token);

        static::assertSame(TokenInterface::AUTHENTICATION_SUCCESSFUL, $token->getAuthenticationStatus());
        static::assertSame($refreshedJwt, $token->getAccount()->getCredentialsSource());
    }

    #[Test]
    public function authenticateStoresRefreshTokenOfNewAuthorizationInSession(): void
    {
        $token = self::createTokenForBearerJwt(JwtFixture::createSignedJwt(['sub' => 'alice', 'exp' => time() + 3600]));
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
        ?HttpClient $httpClient = null
    ): OpenIdConnectProvider {
        $logger = $this->createStub(LoggerInterface::class);
        $client = OpenIdConnectClientFixture::createClient(
            $this->createStub(OAuthClient::class),
            OpenIdConnectClientFixture::createHashService(),
            $logger,
            JwtFixture::createJwks(),
            $httpClient
        );
        $clientFactory = $this->createStub(OpenIdConnectClientFactory::class);
        $clientFactory->method('create')->willReturn($client);

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

    private static function createTokenForBearerJwt(string $jwt): OpenIdConnectToken
    {
        $token = new OpenIdConnectToken();
        $token->updateCredentials(ActionRequest::fromHttpRequest(new ServerRequest('GET', 'https://www.example.com/', ['Authorization' => 'Bearer ' . $jwt])));
        return $token;
    }
}
