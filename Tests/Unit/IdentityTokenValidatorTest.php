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
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

class IdentityTokenValidatorTest extends TestCase
{
    private const string ISSUER = 'https://id.example.com/';
    private const string CLIENT_ID = 'the-client';
    private const int NOW = 1_800_000_000;

    #[Test]
    public function validateReturnsValidatedTokenWithAccountIdentifier(): void
    {
        $identityToken = self::createIdentityToken();

        $validatedIdentityToken = (new IdentityTokenValidator())->validate($identityToken, JwtFixture::createJwks(), self::createRequirements(), self::now());

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
        (new IdentityTokenValidator())->validate(self::createIdentityToken($claims), JwtFixture::createJwks(), self::createRequirements(...$requirements), self::now());
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
        $validatedIdentityToken = (new IdentityTokenValidator())->validate(self::createIdentityToken($claims), JwtFixture::createJwks(), self::createRequirements(...$requirements), self::now());

        static::assertNotSame('', $validatedIdentityToken->accountIdentifier);
    }

    #[Test]
    public function validateRejectsTokenWithTenantPlaceholderButWithoutValidTenant(): void
    {
        $this->expectException(IdentityTokenRejectedException::class);
        $this->expectExceptionCode(1791540862);
        (new IdentityTokenValidator())->validate(
            self::createIdentityToken(['iss' => 'https://login.example.com/../v2.0', 'tid' => '..']),
            JwtFixture::createJwks(),
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
        (new IdentityTokenValidator())->validate(IdentityToken::fromJwt($header . '.' . $forgedClaims . '.' . $signature), JwtFixture::createJwks(), self::createRequirements(), self::now());
    }

    #[Test]
    public function validateRejectsTokenIfNoKeyMatches(): void
    {
        $this->expectException(IdentityTokenRejectedException::class);
        $this->expectExceptionCode(1791540860);
        (new IdentityTokenValidator())->validate(self::createIdentityToken(), [], self::createRequirements(), self::now());
    }

    #[Test]
    public function validateReportsExpiredTokenWhichPassesAllOtherChecks(): void
    {
        $this->expectException(ExpiredIdentityTokenException::class);
        $this->expectExceptionCode(1791540868);
        (new IdentityTokenValidator())->validate(self::createIdentityToken(['exp' => self::NOW - 120]), JwtFixture::createJwks(), self::createRequirements(), self::now());
    }

    #[Test]
    public function validateReportsTokenWithoutExpirationTimeAsExpired(): void
    {
        $this->expectException(ExpiredIdentityTokenException::class);
        (new IdentityTokenValidator())->validate(self::createIdentityToken(['exp' => null]), JwtFixture::createJwks(), self::createRequirements(), self::now());
    }

    #[Test]
    public function validateRejectsExpiredTokenWhichFailsAnotherCheckWithoutReportingItAsExpired(): void
    {
        try {
            (new IdentityTokenValidator())->validate(self::createIdentityToken(['exp' => self::NOW - 120, 'aud' => 'other-client']), JwtFixture::createJwks(), self::createRequirements(), self::now());
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
        (new IdentityTokenValidator())->validate(self::createIdentityToken(['exp' => self::NOW - 30]), JwtFixture::createJwks(), self::createRequirements(leeway: 10), self::now());
    }

    #[Test]
    public function validateEscapesTokenValuesInMessages(): void
    {
        try {
            (new IdentityTokenValidator())->validate(self::createIdentityToken(['iss' => "evil\nissuer"]), JwtFixture::createJwks(), self::createRequirements(), self::now());
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

    private static function now(): DateTimeImmutable
    {
        return new DateTimeImmutable('@' . self::NOW);
    }
}
