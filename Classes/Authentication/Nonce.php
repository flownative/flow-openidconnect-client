<?php
declare(strict_types=1);
namespace Flownative\OpenIdConnect\Client\Authentication;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Http\Cookie;

/**
 * A nonce which binds a login to the browser which started it
 *
 * The browser keeps a random secret in a cookie, and the identity provider receives the hash of this secret as "nonce". The identity
 * provider copies the nonce into the identity token. When the browser returns, the token is only accepted if the browser holds the
 * matching secret. A login started in another browser, or an authorization code taken from another login, is therefore rejected.
 */
#[Flow\Proxy(false)]
final readonly class Nonce
{
    private const string COOKIE_NAME_PREFIX = 'flownative_oidc_nonce_';
    private const int COOKIE_LIFETIME = 3600; # seconds

    private function __construct(
        private string $secret,
        public string $value,
    ) {
    }

    public static function generate(): self
    {
        $secret = bin2hex(random_bytes(32));
        return new self($secret, hash('sha256', $secret));
    }

    /**
     * Tells if the given cookies contain the secret of a nonce value, as found in an identity token
     */
    public static function isBoundToCookies(string $value, array $cookies): bool
    {
        $secret = $cookies[self::getCookieNameForValue($value)] ?? null;
        return is_string($secret) && hash_equals(hash('sha256', $secret), $value);
    }

    /**
     * Each login gets its own cookie, so that logins started in parallel, for example in two tabs, don't replace each other's secret
     */
    public static function getCookieNameForValue(string $value): string
    {
        return self::COOKIE_NAME_PREFIX . substr($value, 0, 16);
    }

    /**
     * Returns the names of the nonce cookies in the given cookies, which belong to logins in progress
     */
    public static function findCookieNames(array $cookies): array
    {
        return array_values(array_filter(
            array_map('strval', array_keys($cookies)),
            static fn (string $cookieName): bool => preg_match('/^' . self::COOKIE_NAME_PREFIX . '[0-9a-f]{16}\z/', $cookieName) === 1
        ));
    }

    public function createCookie(bool $secure): Cookie
    {
        // A "strict" cookie would not be sent when the identity provider redirects the browser back
        return new Cookie(self::getCookieNameForValue($this->value), $this->secret, 0, self::COOKIE_LIFETIME, null, '/', $secure, true, Cookie::SAMESITE_LAX);
    }

    public static function createRemovalCookie(string $cookieName, bool $secure): Cookie
    {
        return new Cookie($cookieName, '', 1, null, null, '/', $secure, true, Cookie::SAMESITE_LAX);
    }
}
