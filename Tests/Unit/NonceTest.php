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

use Flownative\OpenIdConnect\Client\Authentication\Nonce;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

class NonceTest extends TestCase
{
    #[Test]
    public function generateCreatesDifferentNonces(): void
    {
        static::assertNotSame(Nonce::generate()->value, Nonce::generate()->value);
    }

    #[Test]
    public function cookieContainsSecretWhoseHashIsTheNonceValue(): void
    {
        $nonce = Nonce::generate();
        $cookie = $nonce->createCookie(true);

        static::assertSame($nonce->value, hash('sha256', $cookie->getValue()));
        static::assertSame(Nonce::getCookieNameForValue($nonce->value), $cookie->getName());
        static::assertTrue(Nonce::isBoundToCookies($nonce->value, [$cookie->getName() => $cookie->getValue()]));
    }

    #[Test]
    public function cookiesOfDifferentNoncesHaveDifferentNames(): void
    {
        static::assertNotSame(Nonce::generate()->createCookie(true)->getName(), Nonce::generate()->createCookie(true)->getName());
    }

    #[Test]
    public function isBoundToCookiesRejectsMissingCookie(): void
    {
        static::assertFalse(Nonce::isBoundToCookies(Nonce::generate()->value, ['some_cookie' => 'value']));
    }

    #[Test]
    public function isBoundToCookiesRejectsCookieWithAnotherSecret(): void
    {
        $nonce = Nonce::generate();

        static::assertFalse(Nonce::isBoundToCookies($nonce->value, [Nonce::getCookieNameForValue($nonce->value) => str_repeat('0', 64)]));
    }

    #[Test]
    public function isBoundToCookiesRejectsCookieWhichIsNotAString(): void
    {
        $nonce = Nonce::generate();
        $cookie = $nonce->createCookie(true);

        static::assertFalse(Nonce::isBoundToCookies($nonce->value, [$cookie->getName() => [$cookie->getValue()]]));
    }

    #[Test]
    public function findCookieNamesReturnsOnlyNamesOfNonceCookies(): void
    {
        $cookie = Nonce::generate()->createCookie(true);
        $cookies = [
            $cookie->getName() => $cookie->getValue(),
            'flownative_oidc_jwt' => 'jwt',
            'flownative_oidc_nonce_invalid' => 'value',
            'flownative_oidc_nonce_0123456789abcdef-suffix' => 'value',
        ];

        static::assertSame([$cookie->getName()], Nonce::findCookieNames($cookies));
    }

    #[Test]
    public function createRemovalCookieExpiresTheCookie(): void
    {
        static::assertSame('flownative_oidc_nonce_0123456789abcdef=; Expires=Thu, 01-Jan-1970 00:00:01 GMT; Path=/; HttpOnly; SameSite=lax', (string)Nonce::createRemovalCookie('flownative_oidc_nonce_0123456789abcdef', false));
    }
}
