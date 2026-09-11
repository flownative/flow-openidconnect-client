<?php
declare(strict_types=1);
namespace Flownative\OpenIdConnect\Client;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Http\Cookie;

/**
 * The attributes of the cookies which this package sets, taken from the settings of the middleware
 *
 * With "secure" enabled, the cookie names get the prefix "__Host-". Browsers only accept such a cookie if the site itself sets it over
 * HTTPS, so that another subdomain can't plant a cookie with a login of its own.
 */
#[Flow\Proxy(false)]
final readonly class CookieSettings
{
    private const string DEFAULT_JWT_COOKIE_NAME = 'flownative_oidc_jwt';

    private function __construct(
        public bool $secure,
        public bool $httpOnly,
        public string $sameSite,
        private ?string $jwtCookieName, # null if no name is configured
    ) {
    }

    /**
     * The deprecated options "secureCookie" and "cookieName" take precedence over "cookie.secure" and "cookie.name"
     */
    public static function fromMiddlewareSettings(array $settings): self
    {
        $jwtCookieName = $settings['cookieName'] ?? $settings['cookie']['name'] ?? null;
        return new self(
            (bool)($settings['secureCookie'] ?? $settings['cookie']['secure'] ?? true),
            (bool)($settings['cookie']['httpOnly'] ?? true),
            (string)($settings['cookie']['sameSite'] ?? Cookie::SAMESITE_LAX),
            is_string($jwtCookieName) ? $jwtCookieName : null,
        );
    }

    /**
     * A name configured for the authentication provider or the middleware is used as it is
     */
    public function getJwtCookieName(array $providerOptions): string
    {
        $providerCookieName = $providerOptions['jwtCookieName'] ?? null;
        if (is_string($providerCookieName)) {
            return $providerCookieName;
        }
        return $this->jwtCookieName ?? $this->withHostPrefix(self::DEFAULT_JWT_COOKIE_NAME);
    }

    public function withHostPrefix(string $cookieName): string
    {
        return $this->secure ? '__Host-' . $cookieName : $cookieName;
    }
}
