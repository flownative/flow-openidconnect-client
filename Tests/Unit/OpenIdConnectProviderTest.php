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
use Flownative\OpenIdConnect\Client\Authentication\StoredRefreshToken;
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
            'requireVerifiedEmail is not a boolean' => [['serviceName' => 'test', 'roles' => [], 'requireVerifiedEmail' => 'no'], 1789126720],
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
        $token = self::createTokenForBearerJwt(self::createJwt(['email' => 'alice@example.com', 'email_verified' => true]));

        $this->createProvider(['roles' => ['Some.Package:User'], 'accountIdentifierTokenValueName' => 'email'])->authenticate($token);

        static::assertSame('alice@example.com', $token->getAccount()->getAccountIdentifier());
    }

    public static function emailVerifications(): array
    {
        return [
            'verified' => [['email_verified' => true], [], TokenInterface::AUTHENTICATION_SUCCESSFUL],
            'verified as string' => [['email_verified' => 'true'], [], TokenInterface::AUTHENTICATION_SUCCESSFUL],
            'not verified' => [['email_verified' => false], [], TokenInterface::WRONG_CREDENTIALS],
            'not verified as string' => [['email_verified' => 'false'], [], TokenInterface::WRONG_CREDENTIALS],
            'verification as number' => [['email_verified' => 1], [], TokenInterface::WRONG_CREDENTIALS],
            'verification missing' => [[], [], TokenInterface::WRONG_CREDENTIALS],
            'verification not required' => [[], ['requireVerifiedEmail' => false], TokenInterface::AUTHENTICATION_SUCCESSFUL],
        ];
    }

    #[Test]
    #[DataProvider('emailVerifications')]
    public function authenticateRequiresVerifiedEmailAddressAsAccountIdentifier(array $claims, array $options, int $expectedStatus): void
    {
        $token = self::createTokenForBearerJwt(self::createJwt(array_merge(['email' => 'alice@example.com'], $claims)));

        $this->createProvider(array_merge(['roles' => ['Some.Package:User'], 'accountIdentifierTokenValueName' => 'email'], $options))->authenticate($token);

        static::assertSame($expectedStatus, $token->getAuthenticationStatus());
    }

    public static function existingAccountIdentifiers(): array
    {
        return [
            'same identifier' => ['admin@example.com', ['Some.Package:Administrator']],
            'identifier in other case' => ['Admin@Example.com', ['Some.Package:Administrator']],
            'identifier with accent' => ['ádmin@example.com', []],
            'identifier with trailing space' => ['admin@example.com ', []],
        ];
    }

    #[Test]
    #[DataProvider('existingAccountIdentifiers')]
    public function authenticateOnlyAddsRolesOfExistingAccountWithMatchingIdentifier(string $existingAccountIdentifier, array $expectedRoleIdentifiers): void
    {
        $existingAccount = new Account();
        $existingAccount->setAccountIdentifier($existingAccountIdentifier);
        $existingAccount->addRole(new Role('Some.Package:Administrator'));
        // The repository stub mimics a database collation which considers all these identifiers equal.
        $accountRepository = $this->createStub(AccountRepository::class);
        $accountRepository->method('findActiveByAccountIdentifierAndAuthenticationProviderName')->willReturn($existingAccount);
        $token = self::createTokenForBearerJwt(self::createJwt(['email' => 'admin@example.com', 'email_verified' => true]));

        $this->createProvider(['addRolesFromExistingAccount' => true, 'accountIdentifierTokenValueName' => 'email'], accountRepository: $accountRepository)->authenticate($token);

        static::assertSame(TokenInterface::AUTHENTICATION_SUCCESSFUL, $token->getAuthenticationStatus());
        static::assertSame($expectedRoleIdentifiers, array_keys($token->getAccount()->getRoles()));
    }

    #[Test]
    public function authenticateOnlyRequiresVerificationForEmailClaim(): void
    {
        $token = self::createTokenForBearerJwt(self::createJwt(['preferred_username' => 'alice@example.com']));

        $this->createProvider(['roles' => ['Some.Package:User'], 'accountIdentifierTokenValueName' => 'preferred_username'])->authenticate($token);

        static::assertSame(TokenInterface::AUTHENTICATION_SUCCESSFUL, $token->getAuthenticationStatus());
    }

    #[Test]
    public function authenticateRejectsRefreshedTokenWithUnverifiedEmailAddress(): void
    {
        $httpClient = $this->createStub(HttpClient::class);
        $httpClient->method('request')->willReturn(new Response(200, [], json_encode(['id_token' => self::createJwt(['email' => 'alice@example.com', 'email_verified' => false])])));
        $expiredJwt = self::createJwt(['email' => 'alice@example.com', 'email_verified' => true, 'exp' => time() - 600]);
        $token = self::createTokenForCookieJwt($expiredJwt);

        $this->createProvider(['roles' => ['Some.Package:User'], 'accountIdentifierTokenValueName' => 'email'], session: $this->createSession(self::createStoredRefreshToken('the-refresh-token', $expiredJwt)), httpClient: $httpClient)->authenticate($token);

        self::assertNotAuthenticated($token, TokenInterface::WRONG_CREDENTIALS);
    }

    #[Test]
    public function authenticateDoesNotAddRolesOfExistingAccountForUnverifiedEmailAddress(): void
    {
        $accountRepository = $this->createMock(AccountRepository::class);
        $accountRepository->expects($this->never())->method('findActiveByAccountIdentifierAndAuthenticationProviderName');
        $token = self::createTokenForBearerJwt(self::createJwt(['email' => 'admin@example.com', 'email_verified' => false]));

        $this->createProvider(['addRolesFromExistingAccount' => true, 'accountIdentifierTokenValueName' => 'email'], accountRepository: $accountRepository)->authenticate($token);

        self::assertNotAuthenticated($token, TokenInterface::WRONG_CREDENTIALS);
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
        $existingAccount->setAccountIdentifier('alice');
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
        $token = self::createTokenForCookieJwt(self::createJwt(['exp' => time() - 600]));

        $this->createProvider(['roles' => ['Some.Package:User']], session: $this->createSession(null))->authenticate($token);

        self::assertNotAuthenticated($token, TokenInterface::AUTHENTICATION_NEEDED);
    }

    #[Test]
    public function authenticateRefreshesExpiredTokenWithRefreshTokenBoundToIt(): void
    {
        $expiredJwt = self::createJwt(['exp' => time() - 600]);
        $refreshedJwt = self::createJwt();
        $httpClient = $this->createMock(HttpClient::class);
        $httpClient->expects($this->once())
            ->method('request')
            ->with('POST', OpenIdConnectClientFixture::TOKEN_ENDPOINT, $this->callback(
                static fn (array $options): bool => $options['form_params']['grant_type'] === 'refresh_token'
                    && $options['form_params']['refresh_token'] === 'the-refresh-token'
                    && $options['form_params']['client_id'] === OpenIdConnectClientFixture::CLIENT_ID
                    && !isset($options['form_params']['id_token_hint'])
                    && !isset($options['form_params']['prompt'])
            ))
            ->willReturn(new Response(200, [], json_encode(['id_token' => $refreshedJwt])));
        $token = self::createTokenForCookieJwt($expiredJwt);

        $this->createProvider(['roles' => ['Some.Package:User']], session: $this->createSession(self::createStoredRefreshToken('the-refresh-token', $expiredJwt)), httpClient: $httpClient)->authenticate($token);

        static::assertSame(TokenInterface::AUTHENTICATION_SUCCESSFUL, $token->getAuthenticationStatus());
        static::assertSame($refreshedJwt, $token->getAccount()->getCredentialsSource());
    }

    public static function refreshTokensInRefreshResponses(): array
    {
        return [
            'identity provider rotates refresh tokens' => ['the-rotated-refresh-token', 'the-rotated-refresh-token'],
            'identity provider keeps the refresh token' => [null, 'the-refresh-token'],
        ];
    }

    #[Test]
    #[DataProvider('refreshTokensInRefreshResponses')]
    public function authenticateBindsStoredRefreshTokenToRefreshedIdentityToken(?string $refreshTokenInResponse, string $expectedRefreshToken): void
    {
        $expiredJwt = self::createJwt(['exp' => time() - 600]);
        $refreshedJwt = self::createJwt();
        $responseData = ['id_token' => $refreshedJwt];
        if ($refreshTokenInResponse !== null) {
            $responseData['refresh_token'] = $refreshTokenInResponse;
        }
        $httpClient = $this->createStub(HttpClient::class);
        $httpClient->method('request')->willReturn(new Response(200, [], json_encode($responseData)));
        $storedSessionData = null;
        $session = $this->createMock(SessionInterface::class);
        $session->method('isStarted')->willReturn(true);
        $session->method('getData')->willReturnMap([['flownative_oidc_refresh:SomeProvider', self::createStoredRefreshToken('the-refresh-token', $expiredJwt)]]);
        $session->expects($this->once())->method('putData')->with('flownative_oidc_refresh:SomeProvider', $this->anything())->willReturnCallback(
            static function (string $key, mixed $sessionData) use (&$storedSessionData): void {
                $storedSessionData = $sessionData;
            }
        );
        $token = self::createTokenForCookieJwt($expiredJwt);

        $this->createProvider(['roles' => ['Some.Package:User']], session: $session, httpClient: $httpClient)->authenticate($token);

        $storedRefreshToken = StoredRefreshToken::fromSessionData($storedSessionData);
        static::assertSame(TokenInterface::AUTHENTICATION_SUCCESSFUL, $token->getAuthenticationStatus());
        static::assertSame($expectedRefreshToken, $storedRefreshToken->refreshToken);
        static::assertTrue($storedRefreshToken->isBoundTo(IdentityToken::fromJwt($refreshedJwt)));
        static::assertTrue($storedRefreshToken->hasRecentlyReplaced(IdentityToken::fromJwt($expiredJwt), time()));
    }

    public static function storedRefreshTokensNotBoundToTheIdentityToken(): array
    {
        return [
            'refresh token of another identity token of the same subject' => [self::createStoredRefreshToken('the-refresh-token', self::createJwt(['exp' => time() - 300]))],
            'refresh token of another subject' => [self::createStoredRefreshToken('the-refresh-token', self::createJwt(['sub' => 'mallory', 'exp' => time() - 600]))],
            'refresh token without identity token' => [['refreshToken' => 'the-refresh-token', 'refreshedAt' => 0]],
            'refresh token stored by earlier versions' => ['the-refresh-token'],
        ];
    }

    #[Test]
    #[DataProvider('storedRefreshTokensNotBoundToTheIdentityToken')]
    public function authenticateDoesNotUseRefreshTokenWhichIsNotBoundToTheIdentityToken(array|string $storedRefreshToken): void
    {
        $httpClient = $this->createMock(HttpClient::class);
        $httpClient->expects($this->never())->method('request');
        $token = self::createTokenForCookieJwt(self::createJwt(['exp' => time() - 600]));

        $this->createProvider(['roles' => ['Some.Package:User']], session: $this->createSession($storedRefreshToken), httpClient: $httpClient)->authenticate($token);

        self::assertNotAuthenticated($token, TokenInterface::AUTHENTICATION_NEEDED);
    }

    #[Test]
    public function authenticateUsesIdentityTokenOfRecentRefreshForRequestWithPreviousIdentityToken(): void
    {
        $previousJwt = self::createJwt(['exp' => time() - 600]);
        $refreshedJwt = self::createJwt();
        $httpClient = $this->createMock(HttpClient::class);
        $httpClient->expects($this->never())->method('request');
        $session = $this->createMock(SessionInterface::class);
        $session->method('isStarted')->willReturn(true);
        $session->method('getData')->willReturnMap([['flownative_oidc_refresh:SomeProvider', self::createRefreshedStoredRefreshToken($previousJwt, $refreshedJwt, time() - 60)]]);
        $session->expects($this->never())->method('putData');
        $token = self::createTokenForCookieJwt($previousJwt);

        $this->createProvider(['roles' => ['Some.Package:User']], session: $session, httpClient: $httpClient)->authenticate($token);

        static::assertSame(TokenInterface::AUTHENTICATION_SUCCESSFUL, $token->getAuthenticationStatus());
        static::assertSame($refreshedJwt, $token->getAccount()->getCredentialsSource());
    }

    #[Test]
    public function authenticateDoesNotUseIdentityTokenOfRefreshWhichHappenedLongAgo(): void
    {
        $previousJwt = self::createJwt(['exp' => time() - 1200]);
        $httpClient = $this->createMock(HttpClient::class);
        $httpClient->expects($this->never())->method('request');
        $token = self::createTokenForCookieJwt($previousJwt);

        $this->createProvider(['roles' => ['Some.Package:User']], session: $this->createSession(self::createRefreshedStoredRefreshToken($previousJwt, self::createJwt(), time() - 601)), httpClient: $httpClient)->authenticate($token);

        self::assertNotAuthenticated($token, TokenInterface::AUTHENTICATION_NEEDED);
    }

    #[Test]
    public function authenticateRejectsIdentityTokenOfRecentRefreshForAnotherSubject(): void
    {
        $previousJwt = self::createJwt(['exp' => time() - 600]);
        $token = self::createTokenForCookieJwt($previousJwt);

        $this->createProvider(['roles' => ['Some.Package:User']], session: $this->createSession(self::createRefreshedStoredRefreshToken($previousJwt, self::createJwt(['sub' => 'mallory']), time() - 60)))->authenticate($token);

        self::assertNotAuthenticated($token, TokenInterface::WRONG_CREDENTIALS);
    }

    #[Test]
    public function authenticateDoesNotRefreshExpiredBearerToken(): void
    {
        $expiredJwt = self::createJwt(['exp' => time() - 600]);
        $httpClient = $this->createMock(HttpClient::class);
        $httpClient->expects($this->never())->method('request');
        $token = self::createTokenForBearerJwt($expiredJwt);

        $this->createProvider(['roles' => ['Some.Package:User']], session: $this->createSession(self::createStoredRefreshToken('the-refresh-token', $expiredJwt)), httpClient: $httpClient)->authenticate($token);

        self::assertNotAuthenticated($token, TokenInterface::AUTHENTICATION_NEEDED);
    }

    #[Test]
    public function authenticateDoesNotStartSessionToRefreshExpiredToken(): void
    {
        $session = $this->createMock(SessionInterface::class);
        $session->method('canBeResumed')->willReturn(false);
        $session->method('isStarted')->willReturn(false);
        $session->expects($this->never())->method('start');
        $token = self::createTokenForCookieJwt(self::createJwt(['exp' => time() - 600]));

        $this->createProvider(['roles' => ['Some.Package:User']], session: $session)->authenticate($token);

        self::assertNotAuthenticated($token, TokenInterface::AUTHENTICATION_NEEDED);
    }

    #[Test]
    public function authenticateRejectsRefreshedTokenOfAnotherSubject(): void
    {
        $expiredJwt = self::createJwt(['exp' => time() - 600]);
        $httpClient = $this->createStub(HttpClient::class);
        $httpClient->method('request')->willReturn(new Response(200, [], json_encode(['id_token' => self::createJwt(['sub' => 'mallory'])])));
        $token = self::createTokenForCookieJwt($expiredJwt);

        $this->createProvider(['roles' => ['Some.Package:User']], session: $this->createSession(self::createStoredRefreshToken('the-refresh-token', $expiredJwt)), httpClient: $httpClient)->authenticate($token);

        self::assertNotAuthenticated($token, TokenInterface::WRONG_CREDENTIALS);
    }

    #[Test]
    public function authenticateRejectsRefreshedTokenOfAnotherTenant(): void
    {
        $expiredJwt = self::createJwt(['iss' => 'https://login.example.com/tenant-1/v2.0', 'tid' => 'tenant-1', 'exp' => time() - 600]);
        $httpClient = $this->createStub(HttpClient::class);
        $httpClient->method('request')->willReturn(new Response(200, [], json_encode(['id_token' => self::createJwt(['iss' => 'https://login.example.com/tenant-2/v2.0', 'tid' => 'tenant-2'])])));
        $token = self::createTokenForCookieJwt($expiredJwt);

        $this->createProvider(['roles' => ['Some.Package:User']], session: $this->createSession(self::createStoredRefreshToken('the-refresh-token', $expiredJwt)), httpClient: $httpClient, serviceOptions: ['issuer' => 'https://login.example.com/{tenantid}/v2.0'])->authenticate($token);

        self::assertNotAuthenticated($token, TokenInterface::WRONG_CREDENTIALS);
    }

    public static function rejectedRefreshedTokens(): array
    {
        return [
            'identity token of another subject' => [['sub' => 'mallory'], false],
            'identity token with invalid signature' => [['exp' => time() + 7200], true],
        ];
    }

    #[Test]
    #[DataProvider('rejectedRefreshedTokens')]
    public function authenticateDoesNotStoreRotatedRefreshTokenOfRejectedIdentityToken(array $claims, bool $withInvalidSignature): void
    {
        $expiredJwt = self::createJwt(['exp' => time() - 600]);
        $refreshedJwt = $withInvalidSignature ? self::createJwtWithInvalidSignature($claims) : self::createJwt($claims);
        $httpClient = $this->createStub(HttpClient::class);
        $httpClient->method('request')->willReturn(new Response(200, [], json_encode(['id_token' => $refreshedJwt, 'refresh_token' => 'the-rotated-refresh-token'])));
        $session = $this->createMock(SessionInterface::class);
        $session->method('isStarted')->willReturn(true);
        $session->method('getData')->willReturnMap([['flownative_oidc_refresh:SomeProvider', self::createStoredRefreshToken('the-refresh-token', $expiredJwt)]]);
        $session->expects($this->never())->method('putData');
        $token = self::createTokenForCookieJwt($expiredJwt);

        $this->createProvider(['roles' => ['Some.Package:User']], session: $session, httpClient: $httpClient)->authenticate($token);

        self::assertNotAuthenticated($token, TokenInterface::WRONG_CREDENTIALS);
    }

    #[Test]
    public function authenticateDoesNotAcceptRefreshResponseWithoutIdentityTokenString(): void
    {
        $expiredJwt = self::createJwt(['exp' => time() - 600]);
        $httpClient = $this->createStub(HttpClient::class);
        $httpClient->method('request')->willReturn(new Response(200, [], json_encode(['id_token' => ['not' => 'a string']])));
        $token = self::createTokenForCookieJwt($expiredJwt);

        $this->createProvider(['roles' => ['Some.Package:User']], session: $this->createSession(self::createStoredRefreshToken('the-refresh-token', $expiredJwt)), httpClient: $httpClient)->authenticate($token);

        self::assertNotAuthenticated($token, TokenInterface::AUTHENTICATION_NEEDED);
    }

    #[Test]
    public function authenticateRejectsRefreshedTokenWithInvalidSignature(): void
    {
        $expiredJwt = self::createJwt(['exp' => time() - 600]);
        $httpClient = $this->createStub(HttpClient::class);
        $httpClient->method('request')->willReturn(new Response(200, [], json_encode(['id_token' => self::createJwtWithInvalidSignature(['exp' => time() + 7200])])));
        $token = self::createTokenForCookieJwt($expiredJwt);

        $this->createProvider(['roles' => ['Some.Package:User']], session: $this->createSession(self::createStoredRefreshToken('the-refresh-token', $expiredJwt)), httpClient: $httpClient)->authenticate($token);

        self::assertNotAuthenticated($token, TokenInterface::WRONG_CREDENTIALS);
    }

    #[Test]
    public function authenticateRejectsRefreshedTokenForOtherAudience(): void
    {
        $expiredJwt = self::createJwt(['exp' => time() - 600]);
        $httpClient = $this->createStub(HttpClient::class);
        $httpClient->method('request')->willReturn(new Response(200, [], json_encode(['id_token' => self::createJwt(['aud' => 'https://other.example.com'])])));
        $token = self::createTokenForCookieJwt($expiredJwt);

        $this->createProvider(['roles' => ['Some.Package:User']], session: $this->createSession(self::createStoredRefreshToken('the-refresh-token', $expiredJwt)), httpClient: $httpClient)->authenticate($token);

        self::assertNotAuthenticated($token, TokenInterface::WRONG_CREDENTIALS);
    }

    #[Test]
    public function authenticateDoesNotRefreshExpiredTokenIssuedForOtherAudience(): void
    {
        $expiredJwt = self::createJwt(['aud' => 'https://other.example.com', 'exp' => time() - 600]);
        $httpClient = $this->createMock(HttpClient::class);
        $httpClient->expects($this->never())->method('request');
        $token = self::createTokenForCookieJwt($expiredJwt);

        $this->createProvider(['roles' => ['Some.Package:User']], session: $this->createSession(self::createStoredRefreshToken('the-refresh-token', $expiredJwt)), httpClient: $httpClient)->authenticate($token);

        self::assertNotAuthenticated($token, TokenInterface::WRONG_CREDENTIALS);
    }

    #[Test]
    public function authenticateDoesNotStoreRefreshTokenOfRejectedToken(): void
    {
        $token = self::createTokenForFinishedAuthorization(self::createJwt(['aud' => 'https://other.example.com']), 'the-new-refresh-token');
        $session = $this->createMock(SessionInterface::class);
        $session->method('isStarted')->willReturn(true);
        $session->expects($this->never())->method('renewId');
        $session->expects($this->never())->method('putData');

        $this->createProvider(['roles' => ['Some.Package:User']], session: $session)->authenticate($token);

        self::assertNotAuthenticated($token, TokenInterface::WRONG_CREDENTIALS);
    }

    #[Test]
    public function authenticateRenewsExistingSessionAndStoresRefreshTokenAfterLogin(): void
    {
        $jwt = self::createJwt();
        $token = self::createTokenForFinishedAuthorization($jwt, 'the-new-refresh-token');
        $session = $this->createMock(SessionInterface::class);
        $session->method('canBeResumed')->willReturn(true);
        $session->method('isStarted')->willReturn(true);
        $session->expects($this->once())->method('renewId');
        $session->expects($this->once())->method('putData')->with('flownative_oidc_refresh:SomeProvider', self::createStoredRefreshToken('the-new-refresh-token', $jwt));

        $this->createProvider(['roles' => ['Some.Package:User']], session: $session)->authenticate($token);

        static::assertSame(TokenInterface::AUTHENTICATION_SUCCESSFUL, $token->getAuthenticationStatus());
    }

    #[Test]
    public function authenticateStartsSessionForRefreshTokenOfLoginIfNoSessionExists(): void
    {
        $jwt = self::createJwt();
        $token = self::createTokenForFinishedAuthorization($jwt, 'the-new-refresh-token');
        $started = false;
        $session = $this->createMock(SessionInterface::class);
        $session->method('canBeResumed')->willReturn(false);
        $session->method('isStarted')->willReturnCallback(static function () use (&$started): bool {
            return $started;
        });
        $session->expects($this->once())->method('start')->willReturnCallback(static function () use (&$started): void {
            $started = true;
        });
        $session->expects($this->never())->method('renewId');
        $session->expects($this->once())->method('putData')->with('flownative_oidc_refresh:SomeProvider', self::createStoredRefreshToken('the-new-refresh-token', $jwt));

        $this->createProvider(['roles' => ['Some.Package:User']], session: $session)->authenticate($token);

        static::assertSame(TokenInterface::AUTHENTICATION_SUCCESSFUL, $token->getAuthenticationStatus());
    }

    #[Test]
    public function authenticateDoesNotStartSessionForLoginWithoutRefreshToken(): void
    {
        $token = self::createTokenForFinishedAuthorization(self::createJwt(), '');
        $session = $this->createMock(SessionInterface::class);
        $session->method('canBeResumed')->willReturn(false);
        $session->method('isStarted')->willReturn(false);
        $session->expects($this->never())->method('start');
        $session->expects($this->never())->method('putData');

        $this->createProvider(['roles' => ['Some.Package:User']], session: $session)->authenticate($token);

        static::assertSame(TokenInterface::AUTHENTICATION_SUCCESSFUL, $token->getAuthenticationStatus());
    }

    #[Test]
    public function authenticateRemovesRefreshTokenOfEarlierLoginIfLoginHasNone(): void
    {
        $token = self::createTokenForFinishedAuthorization(self::createJwt(), '');
        $session = $this->createMock(SessionInterface::class);
        $session->method('canBeResumed')->willReturn(true);
        $session->method('isStarted')->willReturn(true);
        $session->expects($this->once())->method('renewId');
        $session->expects($this->once())->method('putData')->with('flownative_oidc_refresh:SomeProvider', null);

        $this->createProvider(['roles' => ['Some.Package:User']], session: $session)->authenticate($token);

        static::assertSame(TokenInterface::AUTHENTICATION_SUCCESSFUL, $token->getAuthenticationStatus());
    }

    #[Test]
    public function authenticateDoesNotRenewSessionForTokenFromCookie(): void
    {
        $token = self::createTokenForCookieJwt(self::createJwt());
        $session = $this->createMock(SessionInterface::class);
        $session->method('isStarted')->willReturn(true);
        $session->expects($this->never())->method('renewId');
        $session->expects($this->never())->method('putData');

        $this->createProvider(['roles' => ['Some.Package:User']], session: $session)->authenticate($token);

        static::assertSame(TokenInterface::AUTHENTICATION_SUCCESSFUL, $token->getAuthenticationStatus());
    }

    public static function jwtCookieNames(): array
    {
        return [
            'default name with host prefix' => [[], [], '__Host-flownative_oidc_jwt'],
            'default name without host prefix for insecure cookies' => [[], ['cookie' => ['secure' => false]], 'flownative_oidc_jwt'],
            'name configured for the middleware' => [[], ['cookie' => ['name' => 'middleware_jwt']], 'middleware_jwt'],
            'name configured for the provider' => [['jwtCookieName' => 'provider_jwt'], ['cookie' => ['name' => 'middleware_jwt']], 'provider_jwt'],
        ];
    }

    #[Test]
    #[DataProvider('jwtCookieNames')]
    public function authenticateReadsIdentityTokenFromConfiguredJwtCookie(array $providerOptions, array $middlewareSettings, string $cookieName): void
    {
        $token = new OpenIdConnectToken();
        $token->updateCredentials(ActionRequest::fromHttpRequest((new ServerRequest('GET', 'https://www.example.com/'))->withCookieParams([$cookieName => self::createJwt()])));
        $provider = $this->createProvider(array_merge(['roles' => ['Some.Package:User']], $providerOptions));
        OpenIdConnectClientFixture::inject($provider, 'middlewareSettings', $middlewareSettings);

        $provider->authenticate($token);

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
        OpenIdConnectClientFixture::inject($provider, 'session', $session ?? $this->createSession(null));
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

    private function createSession(array|string|null $storedRefreshToken): SessionInterface
    {
        $session = $this->createStub(SessionInterface::class);
        $session->method('isStarted')->willReturn(true);
        $session->method('getData')->willReturnMap([['flownative_oidc_refresh:SomeProvider', $storedRefreshToken]]);
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

    private static function createStoredRefreshToken(string $refreshToken, string $identityTokenJwt): array
    {
        return StoredRefreshToken::forLogin($refreshToken, IdentityToken::fromJwt($identityTokenJwt))->toSessionData();
    }

    /**
     * The session data as it looks after a request refreshed the previous identity token at the given time
     */
    private static function createRefreshedStoredRefreshToken(string $previousIdentityTokenJwt, string $refreshedIdentityTokenJwt, int $refreshedAt): array
    {
        return StoredRefreshToken::forLogin('the-refresh-token', IdentityToken::fromJwt($previousIdentityTokenJwt))
            ->withRefreshedIdentityToken(IdentityToken::fromJwt($refreshedIdentityTokenJwt), '', $refreshedAt)
            ->toSessionData();
    }

    private static function createTokenForCookieJwt(string $jwt): OpenIdConnectToken
    {
        $token = new OpenIdConnectToken();
        $token->updateCredentials(ActionRequest::fromHttpRequest((new ServerRequest('GET', 'https://www.example.com/'))->withCookieParams(['__Host-flownative_oidc_jwt' => $jwt])));
        return $token;
    }

    /**
     * The token behaves as if the browser had just returned from the identity provider
     */
    private static function createTokenForFinishedAuthorization(string $jwt, string $refreshToken): OpenIdConnectToken
    {
        $token = self::createTokenForCookieJwt($jwt);
        OpenIdConnectClientFixture::inject($token, 'refreshToken', $refreshToken);
        OpenIdConnectClientFixture::inject($token, 'nonceCookieName', '__Host-flownative_oidc_nonce_0123456789abcdef');
        return $token;
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
