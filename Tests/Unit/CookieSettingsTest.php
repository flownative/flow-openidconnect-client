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

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

class CookieSettingsTest extends TestCase
{
    #[Test]
    public function cookiesAreSecureHttpOnlyAndLaxByDefault(): void
    {
        $cookieSettings = CookieSettings::fromMiddlewareSettings([]);

        static::assertTrue($cookieSettings->secure);
        static::assertTrue($cookieSettings->httpOnly);
        static::assertSame('lax', $cookieSettings->sameSite);
    }

    public static function jwtCookieSettings(): array
    {
        return [
            'defaults' => [[], [], true, '__Host-flownative_oidc_jwt'],
            'insecure cookies' => [['cookie' => ['secure' => false]], [], false, 'flownative_oidc_jwt'],
            'deprecated secureCookie overrides cookie.secure' => [['secureCookie' => false, 'cookie' => ['secure' => true]], [], false, 'flownative_oidc_jwt'],
            'cookie.name is used as it is' => [['cookie' => ['name' => 'custom_jwt']], [], true, 'custom_jwt'],
            'deprecated cookieName overrides cookie.name' => [['cookieName' => 'legacy_jwt', 'cookie' => ['name' => 'custom_jwt']], [], true, 'legacy_jwt'],
            'provider option overrides the middleware settings' => [['cookie' => ['name' => 'custom_jwt']], ['jwtCookieName' => 'provider_jwt'], true, 'provider_jwt'],
        ];
    }

    #[Test]
    #[DataProvider('jwtCookieSettings')]
    public function settingsResolveSecureFlagAndJwtCookieName(array $middlewareSettings, array $providerOptions, bool $expectedSecure, string $expectedJwtCookieName): void
    {
        $cookieSettings = CookieSettings::fromMiddlewareSettings($middlewareSettings);

        static::assertSame($expectedSecure, $cookieSettings->secure);
        static::assertSame($expectedJwtCookieName, $cookieSettings->getJwtCookieName($providerOptions));
    }

    #[Test]
    public function withHostPrefixOnlyAddsPrefixForSecureCookies(): void
    {
        static::assertSame('__Host-some_cookie', CookieSettings::fromMiddlewareSettings([])->withHostPrefix('some_cookie'));
        static::assertSame('some_cookie', CookieSettings::fromMiddlewareSettings(['cookie' => ['secure' => false]])->withHostPrefix('some_cookie'));
    }
}
