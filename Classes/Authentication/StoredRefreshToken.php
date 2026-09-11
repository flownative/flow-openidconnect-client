<?php
declare(strict_types=1);
namespace Flownative\OpenIdConnect\Client\Authentication;

use Flownative\OpenIdConnect\Client\IdentityToken;
use Neos\Flow\Annotations as Flow;

/**
 * A refresh token in the session, bound to the identity token which was issued last
 *
 * Only this identity token may be refreshed. An older identity token of the same user, for example from a log file, is useless
 * together with a stolen session. After a refresh, requests which were sent with the previous identity token still receive the
 * refreshed one for a while, because browsers send several requests in parallel.
 */
#[Flow\Proxy(false)]
final readonly class StoredRefreshToken
{
    private const int OVERLAP_AFTER_REFRESH = 600; # seconds

    private function __construct(
        public string $refreshToken,
        public string $identityToken, # the JWT of the identity token which was issued last
        private ?string $previousIdentityTokenHash, # null if no identity token was refreshed since the login
        private int $refreshedAt, # Unix timestamp, 0 if no identity token was refreshed since the login
    ) {
    }

    public static function forLogin(string $refreshToken, IdentityToken $identityToken): self
    {
        return new self($refreshToken, $identityToken->asJwt(), null, 0);
    }

    /**
     * Returns null if the given session data doesn't contain a refresh token in the expected format
     */
    public static function fromSessionData(mixed $sessionData): ?self
    {
        if (!is_array($sessionData)) {
            return null;
        }
        $refreshToken = $sessionData['refreshToken'] ?? null;
        $identityToken = $sessionData['identityToken'] ?? null;
        $previousIdentityTokenHash = $sessionData['previousIdentityTokenHash'] ?? null;
        $refreshedAt = $sessionData['refreshedAt'] ?? null;
        if (!is_string($refreshToken) || $refreshToken === '' || !is_string($identityToken) || $identityToken === ''
            || ($previousIdentityTokenHash !== null && !is_string($previousIdentityTokenHash)) || !is_int($refreshedAt)) {
            return null;
        }
        return new self($refreshToken, $identityToken, $previousIdentityTokenHash, $refreshedAt);
    }

    public function toSessionData(): array
    {
        return [
            'refreshToken' => $this->refreshToken,
            'identityToken' => $this->identityToken,
            'previousIdentityTokenHash' => $this->previousIdentityTokenHash,
            'refreshedAt' => $this->refreshedAt,
        ];
    }

    /**
     * The refresh token of the response replaces the stored one, if the identity provider rotates refresh tokens
     */
    public function withRefreshedIdentityToken(IdentityToken $refreshedIdentityToken, string $newRefreshToken, int $now): self
    {
        return new self($newRefreshToken !== '' ? $newRefreshToken : $this->refreshToken, $refreshedIdentityToken->asJwt(), hash('sha256', $this->identityToken), $now);
    }

    public function isBoundTo(IdentityToken $identityToken): bool
    {
        return hash_equals($this->identityToken, $identityToken->asJwt());
    }

    /**
     * Tells if the given identity token was refreshed a short while ago, so that the stored identity token replaces it
     */
    public function hasRecentlyReplaced(IdentityToken $identityToken, int $now): bool
    {
        return $this->previousIdentityTokenHash !== null
            && $now - $this->refreshedAt <= self::OVERLAP_AFTER_REFRESH
            && hash_equals($this->previousIdentityTokenHash, hash('sha256', $identityToken->asJwt()));
    }
}
