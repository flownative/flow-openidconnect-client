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

use Flownative\OpenIdConnect\Client\Authentication\StoredRefreshToken;
use Flownative\OpenIdConnect\Client\Tests\Unit\Fixtures\JwtFixture;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

class StoredRefreshTokenTest extends TestCase
{
    #[Test]
    public function refreshTokenOfLoginIsBoundToIdentityTokenOfLogin(): void
    {
        $identityToken = self::createIdentityToken('login');
        $storedRefreshToken = StoredRefreshToken::forLogin('the-refresh-token', $identityToken);

        static::assertSame('the-refresh-token', $storedRefreshToken->refreshToken);
        static::assertTrue($storedRefreshToken->isBoundTo($identityToken));
        static::assertFalse($storedRefreshToken->isBoundTo(self::createIdentityToken('other')));
        static::assertFalse($storedRefreshToken->hasRecentlyReplaced(self::createIdentityToken('other'), time()));
    }

    #[Test]
    public function sessionDataContainsAllValues(): void
    {
        $storedRefreshToken = StoredRefreshToken::forLogin('the-refresh-token', self::createIdentityToken('login'))
            ->withRefreshedIdentityToken(self::createIdentityToken('refreshed'), '', 1789140000);

        static::assertEquals($storedRefreshToken, StoredRefreshToken::fromSessionData($storedRefreshToken->toSessionData()));
    }

    public static function invalidSessionData(): array
    {
        $validSessionData = ['refreshToken' => 'the-refresh-token', 'identityToken' => 'the-jwt', 'previousIdentityTokenHash' => null, 'refreshedAt' => 0];
        return [
            'string of earlier versions' => ['the-refresh-token'],
            'missing refresh token' => [array_diff_key($validSessionData, ['refreshToken' => true])],
            'empty refresh token' => [array_merge($validSessionData, ['refreshToken' => ''])],
            'missing identity token' => [array_diff_key($validSessionData, ['identityToken' => true])],
            'previous identity token hash is not a string' => [array_merge($validSessionData, ['previousIdentityTokenHash' => 123])],
            'refresh time is not an integer' => [array_merge($validSessionData, ['refreshedAt' => '0'])],
        ];
    }

    #[Test]
    #[DataProvider('invalidSessionData')]
    public function fromSessionDataReturnsNullForInvalidData(mixed $sessionData): void
    {
        static::assertNull(StoredRefreshToken::fromSessionData($sessionData));
    }

    #[Test]
    public function refreshedIdentityTokenReplacesThePreviousOne(): void
    {
        $previousIdentityToken = self::createIdentityToken('previous');
        $refreshedIdentityToken = self::createIdentityToken('refreshed');

        $storedRefreshToken = StoredRefreshToken::forLogin('the-refresh-token', $previousIdentityToken)->withRefreshedIdentityToken($refreshedIdentityToken, '', time());

        static::assertSame('the-refresh-token', $storedRefreshToken->refreshToken);
        static::assertTrue($storedRefreshToken->isBoundTo($refreshedIdentityToken));
        static::assertFalse($storedRefreshToken->isBoundTo($previousIdentityToken));
        static::assertTrue($storedRefreshToken->hasRecentlyReplaced($previousIdentityToken, time()));
        static::assertFalse($storedRefreshToken->hasRecentlyReplaced(self::createIdentityToken('other'), time()));
    }

    #[Test]
    public function rotatedRefreshTokenReplacesTheStoredOne(): void
    {
        $storedRefreshToken = StoredRefreshToken::forLogin('the-refresh-token', self::createIdentityToken('previous'))
            ->withRefreshedIdentityToken(self::createIdentityToken('refreshed'), 'the-rotated-refresh-token', time());

        static::assertSame('the-rotated-refresh-token', $storedRefreshToken->refreshToken);
    }

    #[Test]
    public function previousIdentityTokenIsOnlyReplacedForTenMinutesAfterTheRefresh(): void
    {
        $previousIdentityToken = self::createIdentityToken('previous');
        $storedRefreshToken = StoredRefreshToken::forLogin('the-refresh-token', $previousIdentityToken)->withRefreshedIdentityToken(self::createIdentityToken('refreshed'), '', 1789140000);

        static::assertTrue($storedRefreshToken->hasRecentlyReplaced($previousIdentityToken, 1789140000 + 600));
        static::assertFalse($storedRefreshToken->hasRecentlyReplaced($previousIdentityToken, 1789140000 + 601));
    }

    private static function createIdentityToken(string $tokenIdentifier): IdentityToken
    {
        return IdentityToken::fromJwt(JwtFixture::createSignedJwt(['sub' => 'alice', 'exp' => time() + 3600, 'jti' => $tokenIdentifier]));
    }
}
