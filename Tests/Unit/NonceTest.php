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

use Flownative\OAuth2\Client\BrowserBinding;
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
        $cookieSettings = self::createCookieSettings();
        $nonce = Nonce::generate();
        $cookie = $nonce->createCookie($cookieSettings);

        static::assertSame($nonce->value, hash('sha256', $cookie->getValue()));
        static::assertSame(Nonce::getCookieNameForValue($nonce->value, $cookieSettings), $cookie->getName());
        static::assertTrue(Nonce::isBoundToCookies($nonce->value, [$cookie->getName() => $cookie->getValue()], $cookieSettings));
    }

    #[Test]
    public function cookieNameHasHostPrefixOnlyIfCookieIsSecure(): void
    {
        $nonce = Nonce::generate();

        static::assertStringStartsWith('__Host-flownative_oidc_nonce_', $nonce->createCookie(self::createCookieSettings())->getName());
        static::assertStringStartsWith('flownative_oidc_nonce_', $nonce->createCookie(self::createCookieSettings(false))->getName());
    }

    #[Test]
    public function cookiesOfDifferentNoncesHaveDifferentNames(): void
    {
        $cookieSettings = self::createCookieSettings();

        static::assertNotSame(Nonce::generate()->createCookie($cookieSettings)->getName(), Nonce::generate()->createCookie($cookieSettings)->getName());
    }

    #[Test]
    public function isBoundToCookiesRejectsMissingCookie(): void
    {
        static::assertFalse(Nonce::isBoundToCookies(Nonce::generate()->value, ['some_cookie' => 'value'], self::createCookieSettings()));
    }

    #[Test]
    public function isBoundToCookiesRejectsCookieWithAnotherSecret(): void
    {
        $cookieSettings = self::createCookieSettings();
        $nonce = Nonce::generate();

        static::assertFalse(Nonce::isBoundToCookies($nonce->value, [Nonce::getCookieNameForValue($nonce->value, $cookieSettings) => str_repeat('0', 64)], $cookieSettings));
    }

    #[Test]
    public function isBoundToCookiesRejectsCookieWhichIsNotAString(): void
    {
        $cookieSettings = self::createCookieSettings();
        $nonce = Nonce::generate();
        $cookie = $nonce->createCookie($cookieSettings);

        static::assertFalse(Nonce::isBoundToCookies($nonce->value, [$cookie->getName() => [$cookie->getValue()]], $cookieSettings));
    }

    #[Test]
    public function isBoundToCookiesRejectsCookieWithoutHostPrefixIfCookiesAreSecure(): void
    {
        $nonce = Nonce::generate();
        $cookieWithoutPrefix = $nonce->createCookie(self::createCookieSettings(false));

        static::assertFalse(Nonce::isBoundToCookies($nonce->value, [$cookieWithoutPrefix->getName() => $cookieWithoutPrefix->getValue()], self::createCookieSettings()));
    }

    #[Test]
    public function findCookieNamesReturnsOnlyNamesOfNonceCookies(): void
    {
        $cookieSettings = self::createCookieSettings();
        $cookie = Nonce::generate()->createCookie($cookieSettings);
        $cookies = [
            $cookie->getName() => $cookie->getValue(),
            '__Host-flownative_oidc_jwt' => 'jwt',
            'flownative_oidc_nonce_0123456789abcdef' => 'without host prefix',
            '__Host-flownative_oidc_nonce_invalid' => 'value',
            '__Host-flownative_oidc_nonce_0123456789abcdef-suffix' => 'value',
        ];

        static::assertSame([$cookie->getName()], Nonce::findCookieNames($cookies, $cookieSettings));
    }

    #[Test]
    public function createBrowserBindingUsesTheCookieOfTheNonce(): void
    {
        $nonce = Nonce::generate();
        $cookie = $nonce->createCookie(self::createCookieSettings());

        $browserBinding = $nonce->createBrowserBinding(self::createCookieSettings());

        self::assertSame($cookie->getName(), $browserBinding->cookieName);
        self::assertSame($nonce->value, $browserBinding->getSecretHash());
        self::assertTrue(BrowserBinding::isPresentInCookies($browserBinding->cookieName, $browserBinding->getSecretHash(), [$cookie->getName() => $cookie->getValue()]));
    }

    #[Test]
    public function createRemovalCookieExpiresTheCookie(): void
    {
        static::assertSame('flownative_oidc_nonce_0123456789abcdef=; Expires=Thu, 01-Jan-1970 00:00:01 GMT; Path=/; HttpOnly; SameSite=lax', (string)Nonce::createRemovalCookie('flownative_oidc_nonce_0123456789abcdef', self::createCookieSettings(false)));
    }

    private static function createCookieSettings(bool $secure = true): CookieSettings
    {
        return CookieSettings::fromMiddlewareSettings(['cookie' => ['secure' => $secure]]);
    }
}
