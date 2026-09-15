<?php
declare(strict_types=1);
namespace Flownative\OpenIdConnect\Client\Authentication;

use Flownative\OpenIdConnect\Client\IdentityToken;
use Neos\Flow\Annotations as Flow;

/**
 * A refresh token in the session, bound to the generation of identity tokens which was issued last
 *
 * A generation consists of the identity token of the login, or of all identity tokens which were issued by refreshing the same
 * generation. Browsers send several requests in parallel, so several requests may refresh the same identity token, and the browser
 * keeps any of their results. Only identity tokens of the current generation may be refreshed. An older identity token of the same
 * user, for example from a log file, is useless together with a stolen session. After a refresh, requests which were sent with an
 * identity token of the previous generation still receive the refreshed one for a while.
 */
#[Flow\Proxy(false)]
final readonly class StoredRefreshToken
{
    private const int OVERLAP_AFTER_REFRESH = 600; # seconds

    /**
     * @param string[] $identityTokenHashes
     * @param string[] $previousIdentityTokenHashes
     */
    private function __construct(
        public string $refreshToken,
        public string $identityToken, # the JWT of the identity token which was issued last
        private array $identityTokenHashes, # SHA-256 hashes of the identity tokens of the current generation
        private array $previousIdentityTokenHashes, # empty if no identity token was refreshed since the login
        private int $refreshedAt, # Unix timestamp of the first refresh of the previous generation, 0 if nothing was refreshed since the login
    ) {
    }

    public static function forLogin(string $refreshToken, IdentityToken $identityToken): self
    {
        return new self($refreshToken, $identityToken->asJwt(), [self::hash($identityToken->asJwt())], [], 0);
    }

    /**
     * Returns null if the given session data doesn't contain a refresh token in the expected format
     *
     * Session data of version 6.0.0, which only knows one identity token per generation, is accepted as well.
     */
    public static function fromSessionData(mixed $sessionData): ?self
    {
        if (!is_array($sessionData)) {
            return null;
        }
        $refreshToken = $sessionData['refreshToken'] ?? null;
        $identityToken = $sessionData['identityToken'] ?? null;
        $refreshedAt = $sessionData['refreshedAt'] ?? null;
        if (!is_string($refreshToken) || $refreshToken === '' || !is_string($identityToken) || $identityToken === '' || !is_int($refreshedAt)) {
            return null;
        }

        if (!array_key_exists('identityTokenHashes', $sessionData)) {
            $previousIdentityTokenHash = $sessionData['previousIdentityTokenHash'] ?? null;
            if ($previousIdentityTokenHash !== null && !is_string($previousIdentityTokenHash)) {
                return null;
            }
            return new self($refreshToken, $identityToken, [self::hash($identityToken)], $previousIdentityTokenHash !== null ? [$previousIdentityTokenHash] : [], $refreshedAt);
        }

        $identityTokenHashes = $sessionData['identityTokenHashes'];
        $previousIdentityTokenHashes = $sessionData['previousIdentityTokenHashes'] ?? null;
        if ($identityTokenHashes === [] || !self::isListOfStrings($identityTokenHashes) || !self::isListOfStrings($previousIdentityTokenHashes)) {
            return null;
        }
        return new self($refreshToken, $identityToken, $identityTokenHashes, $previousIdentityTokenHashes, $refreshedAt);
    }

    public function toSessionData(): array
    {
        return [
            'refreshToken' => $this->refreshToken,
            'identityToken' => $this->identityToken,
            'identityTokenHashes' => $this->identityTokenHashes,
            'previousIdentityTokenHashes' => $this->previousIdentityTokenHashes,
            'refreshedAt' => $this->refreshedAt,
        ];
    }

    /**
     * Starts a new generation with the given identity token, which was issued by refreshing an identity token of the current generation
     *
     * The refresh token of the response replaces the stored one, if the identity provider rotates refresh tokens.
     */
    public function withRefreshedIdentityToken(IdentityToken $refreshedIdentityToken, string $newRefreshToken, int $now): self
    {
        return new self(
            $newRefreshToken !== '' ? $newRefreshToken : $this->refreshToken,
            $refreshedIdentityToken->asJwt(),
            [self::hash($refreshedIdentityToken->asJwt())],
            $this->identityTokenHashes,
            $now
        );
    }

    /**
     * Adds the given identity token to the current generation, because a parallel request refreshed an identity token of the previous
     * generation as well
     *
     * The refresh token of the response replaces the stored one, if the identity provider rotates refresh tokens.
     */
    public function withIdentityTokenOfParallelRefresh(IdentityToken $refreshedIdentityToken, string $newRefreshToken): self
    {
        $refreshedIdentityTokenHash = self::hash($refreshedIdentityToken->asJwt());
        return new self(
            $newRefreshToken !== '' ? $newRefreshToken : $this->refreshToken,
            $refreshedIdentityToken->asJwt(),
            self::containsHash($this->identityTokenHashes, $refreshedIdentityTokenHash) ? $this->identityTokenHashes : [...$this->identityTokenHashes, $refreshedIdentityTokenHash],
            $this->previousIdentityTokenHashes,
            $this->refreshedAt
        );
    }

    /**
     * Tells if the given identity token belongs to the current generation and may be refreshed
     */
    public function isBoundTo(IdentityToken $identityToken): bool
    {
        return self::containsHash($this->identityTokenHashes, self::hash($identityToken->asJwt()));
    }

    /**
     * Tells if the given identity token belongs to the previous generation, which was refreshed a short while ago
     */
    public function hasRecentlyReplaced(IdentityToken $identityToken, int $now): bool
    {
        return $this->previousIdentityTokenHashes !== []
            && $now - $this->refreshedAt <= self::OVERLAP_AFTER_REFRESH
            && self::containsHash($this->previousIdentityTokenHashes, self::hash($identityToken->asJwt()));
    }

    private static function hash(string $jwt): string
    {
        return hash('sha256', $jwt);
    }

    /**
     * @param string[] $hashes
     */
    private static function containsHash(array $hashes, string $hash): bool
    {
        foreach ($hashes as $candidate) {
            if (hash_equals($candidate, $hash)) {
                return true;
            }
        }
        return false;
    }

    private static function isListOfStrings(mixed $value): bool
    {
        return is_array($value) && array_is_list($value) && array_filter($value, static fn (mixed $item): bool => !is_string($item)) === [];
    }
}
