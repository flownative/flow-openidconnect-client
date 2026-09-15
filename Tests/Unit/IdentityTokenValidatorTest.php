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

use DateTimeImmutable;
use Flownative\OpenIdConnect\Client\Tests\Unit\Fixtures\JwtFixture;
use Flownative\OpenIdConnect\Client\Tests\Unit\Fixtures\OpenIdConnectClientFixture;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;

class IdentityTokenValidatorTest extends TestCase
{
    private const string ISSUER = 'https://id.example.com/';
    private const string CLIENT_ID = 'the-client';
    private const int NOW = 1_800_000_000;

    #[Test]
    public function validateReturnsValidatedTokenWithAccountIdentifier(): void
    {
        $identityToken = self::createIdentityToken();

        $validatedIdentityToken = (new IdentityTokenValidator())->validate($identityToken, $this->createClient(), self::createRequirements(), self::now());

        static::assertSame($identityToken, $validatedIdentityToken->identityToken);
        static::assertSame('alice', $validatedIdentityToken->accountIdentifier);
    }

    public static function rejectedTokens(): array
    {
        return [
            'other issuer' => [['iss' => 'https://evil.example.com/'], [], 1791540862],
            'no issuer' => [['iss' => null], [], 1791540862],
            'other audience' => [['aud' => 'other-client'], [], 1791540863],
            'azp naming another client' => [['azp' => 'other-client'], [], 1791540870],
            'azp which is not a string' => [['azp' => 42], [], 1791540870],
            'several audiences without azp' => [['aud' => [self::CLIENT_ID, 'https://api.example.com']], [], 1791540869],
            'issued in the future' => [['iat' => self::NOW + 120], [], 1791540864],
            'not valid before the future' => [['nbf' => self::NOW + 120], [], 1791540864],
            'nonce missing' => [[], ['nonce' => 'the-nonce'], 1791540865],
            'other nonce' => [['nonce' => 'another-nonce'], ['nonce' => 'the-nonce'], 1791540865],
            'nonce which is not a string' => [['nonce' => ['the-nonce']], ['nonce' => 'the-nonce'], 1791540865],
            'account identifier missing' => [['sub' => null], [], 1791540866],
            'account identifier empty' => [['sub' => ''], [], 1791540866],
            'account identifier not a string' => [['sub' => 42], [], 1791540866],
            'unverified email address as account identifier' => [['email' => 'alice@example.com', 'email_verified' => false], ['accountIdentifierClaimName' => 'email'], 1791540867],
            'email address without verification as account identifier' => [['email' => 'alice@example.com'], ['accountIdentifierClaimName' => 'email'], 1791540867],
        ];
    }

    #[Test]
    #[DataProvider('rejectedTokens')]
    public function validateRejectsTokenWhichFailsACheck(array $claims, array $requirements, int $expectedExceptionCode): void
    {
        $this->expectException(IdentityTokenRejectedException::class);
        $this->expectExceptionCode($expectedExceptionCode);
        (new IdentityTokenValidator())->validate(self::createIdentityToken($claims), $this->createClient(), self::createRequirements(...$requirements), self::now());
    }

    public static function acceptedTokens(): array
    {
        return [
            'azp naming the client' => [['azp' => self::CLIENT_ID], []],
            'several audiences with azp naming the client' => [['aud' => [self::CLIENT_ID, 'https://api.example.com'], 'azp' => self::CLIENT_ID], []],
            'several audiences without azp if azp is not checked' => [['aud' => ['https://api.example.com', 'https://id.example.com/userinfo']], ['audiences' => ['https://api.example.com'], 'authorizedParty' => null]],
            'azp of another client if azp is not checked' => [['aud' => ['https://api.example.com', 'https://id.example.com/userinfo'], 'azp' => 'other-client'], ['audiences' => ['https://api.example.com'], 'authorizedParty' => null]],
            'one of several issuers' => [['iss' => 'https://other.example.com/'], ['issuers' => [self::ISSUER, 'https://other.example.com/']]],
            'issuer with tenant placeholder' => [['iss' => 'https://login.example.com/tenant-1/v2.0', 'tid' => 'tenant-1'], ['issuers' => ['https://login.example.com/{tenantid}/v2.0']]],
            'issued within the leeway' => [['iat' => self::NOW + 30, 'nbf' => self::NOW + 30], []],
            'expected nonce' => [['nonce' => 'the-nonce'], ['nonce' => 'the-nonce']],
            'verified email address as account identifier' => [['email' => 'alice@example.com', 'email_verified' => true], ['accountIdentifierClaimName' => 'email']],
            'email address as account identifier without required verification' => [['email' => 'alice@example.com'], ['accountIdentifierClaimName' => 'email', 'requireVerifiedEmail' => false]],
            'expired within the leeway' => [['exp' => self::NOW - 30], []],
        ];
    }

    #[Test]
    #[DataProvider('acceptedTokens')]
    public function validateAcceptsTokenWhichPassesAllChecks(array $claims, array $requirements): void
    {
        $validatedIdentityToken = (new IdentityTokenValidator())->validate(self::createIdentityToken($claims), $this->createClient(), self::createRequirements(...$requirements), self::now());

        static::assertNotSame('', $validatedIdentityToken->accountIdentifier);
    }

    #[Test]
    public function validateRejectsTokenWithTenantPlaceholderButWithoutValidTenant(): void
    {
        $this->expectException(IdentityTokenRejectedException::class);
        $this->expectExceptionCode(1791540862);
        (new IdentityTokenValidator())->validate(
            self::createIdentityToken(['iss' => 'https://login.example.com/../v2.0', 'tid' => '..']),
            $this->createClient(),
            self::createRequirements(issuers: ['https://login.example.com/{tenantid}/v2.0']),
            self::now()
        );
    }

    #[Test]
    public function validateRejectsTokenWithInvalidSignature(): void
    {
        [$header, , $signature] = explode('.', JwtFixture::createSignedJwt(self::createClaims([])));
        [, $forgedClaims] = explode('.', JwtFixture::createSignedJwt(self::createClaims(['sub' => 'mallory'])));

        $this->expectException(IdentityTokenRejectedException::class);
        $this->expectExceptionCode(1791540861);
        (new IdentityTokenValidator())->validate(IdentityToken::fromJwt($header . '.' . $forgedClaims . '.' . $signature), $this->createClient(), self::createRequirements(), self::now());
    }

    #[Test]
    public function validateRejectsTokenIfNoKeyMatches(): void
    {
        $this->expectException(IdentityTokenRejectedException::class);
        $this->expectExceptionCode(1791540860);
        $httpClient = $this->createStub(HttpClient::class);
        $httpClient->method('request')->willReturn(self::createJwksResponse(JwtFixture::ROTATED_KEY_IDENTIFIER));
        (new IdentityTokenValidator())->validate(self::createIdentityToken(), $this->createClient(JwtFixture::createJwks(JwtFixture::ROTATED_KEY_IDENTIFIER), $httpClient), self::createRequirements(), self::now());
    }

    #[Test]
    public function validateReloadsKeySetForTokenOfExpectedIssuerSignedWithUnknownKey(): void
    {
        $httpClient = $this->createMock(HttpClient::class);
        $httpClient->expects($this->once())->method('request')->with('GET', OpenIdConnectClientFixture::JWKS_URI)->willReturn(self::createJwksResponse(JwtFixture::KEY_IDENTIFIER, JwtFixture::ROTATED_KEY_IDENTIFIER));
        $identityToken = IdentityToken::fromJwt(JwtFixture::createSignedJwt(self::createClaims([]), JwtFixture::ROTATED_KEY_IDENTIFIER));

        $validatedIdentityToken = (new IdentityTokenValidator())->validate($identityToken, $this->createClient(httpClient: $httpClient), self::createRequirements(), self::now());

        static::assertSame('alice', $validatedIdentityToken->accountIdentifier);
    }

    #[Test]
    public function validateDoesNotReloadKeySetForTokenOfAnotherIssuer(): void
    {
        $httpClient = $this->createMock(HttpClient::class);
        $httpClient->expects($this->never())->method('request');
        $identityToken = IdentityToken::fromJwt(JwtFixture::createSignedJwt(self::createClaims(['iss' => 'https://evil.example.com/']), JwtFixture::ROTATED_KEY_IDENTIFIER));

        $this->expectException(IdentityTokenRejectedException::class);
        (new IdentityTokenValidator())->validate($identityToken, $this->createClient(httpClient: $httpClient), self::createRequirements(), self::now());
    }

    #[Test]
    public function validateReportsKeySetWhichCannotBeReloaded(): void
    {
        $httpClient = $this->createStub(HttpClient::class);
        $httpClient->method('request')->willThrowException(new ConnectException('Connection refused', new Request('GET', OpenIdConnectClientFixture::JWKS_URI)));
        $identityToken = IdentityToken::fromJwt(JwtFixture::createSignedJwt(self::createClaims([]), JwtFixture::ROTATED_KEY_IDENTIFIER));

        $this->expectException(ConnectionException::class);
        (new IdentityTokenValidator())->validate($identityToken, $this->createClient(httpClient: $httpClient), self::createRequirements(), self::now());
    }

    #[Test]
    public function validateReportsExpiredTokenWhichPassesAllOtherChecks(): void
    {
        $this->expectException(ExpiredIdentityTokenException::class);
        $this->expectExceptionCode(1791540868);
        (new IdentityTokenValidator())->validate(self::createIdentityToken(['exp' => self::NOW - 120]), $this->createClient(), self::createRequirements(), self::now());
    }

    #[Test]
    public function validateReportsTokenWithoutExpirationTimeAsExpired(): void
    {
        $this->expectException(ExpiredIdentityTokenException::class);
        (new IdentityTokenValidator())->validate(self::createIdentityToken(['exp' => null]), $this->createClient(), self::createRequirements(), self::now());
    }

    #[Test]
    public function validateRejectsExpiredTokenWhichFailsAnotherCheckWithoutReportingItAsExpired(): void
    {
        try {
            (new IdentityTokenValidator())->validate(self::createIdentityToken(['exp' => self::NOW - 120, 'aud' => 'other-client']), $this->createClient(), self::createRequirements(), self::now());
            static::fail('The token was not rejected');
        } catch (IdentityTokenRejectedException $exception) {
            static::assertNotInstanceOf(ExpiredIdentityTokenException::class, $exception);
            static::assertSame(1791540863, $exception->getCode());
        }
    }

    #[Test]
    public function validateUsesConfiguredLeeway(): void
    {
        $this->expectException(ExpiredIdentityTokenException::class);
        (new IdentityTokenValidator())->validate(self::createIdentityToken(['exp' => self::NOW - 30]), $this->createClient(), self::createRequirements(leeway: 10), self::now());
    }

    #[Test]
    public function validateEscapesTokenValuesInMessages(): void
    {
        try {
            (new IdentityTokenValidator())->validate(self::createIdentityToken(['iss' => "evil\nissuer"]), $this->createClient(), self::createRequirements(), self::now());
            static::fail('The token was not rejected');
        } catch (IdentityTokenRejectedException $exception) {
            static::assertStringNotContainsString("\n", $exception->getMessage());
        }
    }

    private static function createIdentityToken(array $claims = []): IdentityToken
    {
        return IdentityToken::fromJwt(JwtFixture::createSignedJwt(self::createClaims($claims)));
    }

    private static function createClaims(array $claims): array
    {
        $defaultClaims = [
            'iss' => self::ISSUER,
            'aud' => self::CLIENT_ID,
            'sub' => 'alice',
            'iat' => self::NOW - 10,
            'exp' => self::NOW + 3600,
        ];
        return array_filter(array_merge($defaultClaims, $claims), static fn (mixed $value): bool => $value !== null);
    }

    private static function createRequirements(
        array $issuers = [self::ISSUER],
        array $audiences = [self::CLIENT_ID],
        ?string $authorizedParty = self::CLIENT_ID,
        string $accountIdentifierClaimName = 'sub',
        bool $requireVerifiedEmail = true,
        int $leeway = 60,
        ?string $nonce = null,
    ): IdentityTokenRequirements {
        return new IdentityTokenRequirements($issuers, $audiences, $authorizedParty, $accountIdentifierClaimName, $requireVerifiedEmail, $leeway, $nonce);
    }

    private function createClient(?array $jwks = null, ?HttpClient $httpClient = null): OpenIdConnectClient
    {
        return OpenIdConnectClientFixture::createClient($this->createStub(OAuthClient::class), OpenIdConnectClientFixture::createHashService(), $this->createStub(LoggerInterface::class), $jwks ?? JwtFixture::createJwks(), $httpClient);
    }

    private static function createJwksResponse(string ...$keyIdentifiers): Response
    {
        return new Response(200, [], json_encode(['keys' => JwtFixture::createJwks(...$keyIdentifiers)], JSON_THROW_ON_ERROR));
    }

    private static function now(): DateTimeImmutable
    {
        return new DateTimeImmutable('@' . self::NOW);
    }
}
