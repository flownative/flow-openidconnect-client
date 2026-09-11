<?php
declare(strict_types=1);

namespace Flownative\OpenIdConnect\Client;

use DateTimeInterface;
use InvalidArgumentException;
use JsonException;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Exception as JwtException;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\UnencryptedToken;
use Neos\Utility\Arrays;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;
use phpseclib3\Exception\NoKeyLoadedException;
use phpseclib3\Math\BigInteger;

/**
 * Value object for an OpenID Connect identity token
 *
 * Creating an identity token only checks its structure. Code using the token must verify
 * the signature and the claims before trusting any of its values.
 *
 * @see https://openid.net/specs/openid-connect-core-1_0.html#IDToken
 */
class IdentityToken
{
    private const array SUPPORTED_ALGORITHMS = ['RS256', 'RS384', 'RS512'];

    public array $values = [];
    private array $header;
    private string $jwt;
    private UnencryptedToken $parsedJwt;
    private string $payload;
    private string $signature;

    /**
     * @see https://tools.ietf.org/html/rfc7519
     */
    public static function fromJwt(string $jwt): IdentityToken
    {
        $identityToken = new static();
        $identityToken->jwt = $jwt;

        if (preg_match('/^[a-zA-Z0-9=_-]+\.([a-zA-Z0-9=_-]+\.)+[a-zA-Z0-9=_-]+$/', $jwt) !== 1) {
            throw new InvalidArgumentException('The given string was not a valid encoded identity token.', 1559204596);
        }

        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            throw new InvalidArgumentException('The given JWT does not have exactly 3 parts (header, payload, signature), which is currently not supported by this implementation.', 1559208004);
        }

        // The JSON Web Signature (JWS), see https://tools.ietf.org/html/rfc7515
        $identityToken->signature = self::base64UrlDecode(array_pop($parts));
        if (empty($identityToken->signature)) {
            throw new InvalidArgumentException('Failed decoding signature from JWT.', 1559207444);
        }

        // The JOSE Header (JSON Object Signing and Encryption), see: https://tools.ietf.org/html/rfc7515
        try {
            $header = json_decode(self::base64UrlDecode($parts[0]), true, 512, JSON_THROW_ON_ERROR);
            if (!is_array($header)) {
                throw new InvalidArgumentException('Failed decoding JOSE header from JWT.', 1559207497);
            }
            $identityToken->header = $header;
        } catch (JsonException $e) {
            throw new InvalidArgumentException('Failed decoding JOSE header from JWT.', 1603362934, $e);
        }
        if (!isset($identityToken->header['alg'])) {
            throw new InvalidArgumentException('Missing signature algorithm in JOSE header from JWT.', 1559212231);
        }
        if (!is_string($identityToken->header['alg'])) {
            throw new InvalidArgumentException('The signature algorithm in the JOSE header of the JWT is not a string.', 1789122172);
        }
        if (isset($identityToken->header['kid']) && !is_string($identityToken->header['kid'])) {
            throw new InvalidArgumentException('The key identifier in the JOSE header of the JWT is not a string.', 1789122173);
        }
        // No header extensions are supported, so tokens marking any extension as critical must be rejected (RFC 7515, section 4.1.11).
        if (array_key_exists('crit', $identityToken->header)) {
            throw new InvalidArgumentException('The JWT uses critical header extensions, which are not supported.', 1789123616);
        }

        // The JWT payload, including header, sans signature
        $identityToken->payload = implode('.', $parts);

        try {
            $identityTokenArray = json_decode(self::base64UrlDecode($parts[1]), true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new InvalidArgumentException('Failed decoding identity token from JWT.', 1603362918, $e);
        }
        if (!is_array($identityTokenArray)) {
            throw new InvalidArgumentException('Failed decoding identity token from JWT.', 1559208043);
        }

        // The parser only accepts numbers and strings as time claims and throws a TypeError for any other type.
        foreach ([RegisteredClaims::EXPIRATION_TIME, RegisteredClaims::NOT_BEFORE, RegisteredClaims::ISSUED_AT] as $timeClaimName) {
            if (array_key_exists($timeClaimName, $identityTokenArray) && !is_int($identityTokenArray[$timeClaimName]) && !is_float($identityTokenArray[$timeClaimName]) && !is_string($identityTokenArray[$timeClaimName])) {
                throw new InvalidArgumentException(sprintf('The claim "%s" of the JWT is not a valid time.', $timeClaimName), 1789122174);
            }
        }

        try {
            $parsedJwt = (new Parser(new JoseEncoder()))->parse($jwt);
        } catch (JwtException $exception) {
            throw new InvalidArgumentException('Failed parsing the claims of the JWT.', 1789122174, $exception);
        }
        if (!$parsedJwt instanceof UnencryptedToken) {
            throw new InvalidArgumentException('Failed parsing the claims of the JWT.', 1789122174);
        }

        $identityToken->values = $identityTokenArray;
        $identityToken->parsedJwt = $parsedJwt;
        return $identityToken;
    }

    public function asJwt(): string
    {
        return $this->jwt;
    }

    /**
     * Verifies the signature (JWS) of this token with the matching keys of the given JSON Web Key Set
     *
     * If the token names a key identifier, only the key with this identifier is used. Otherwise,
     * every key which is suitable for the algorithm of the token is tried.
     *
     * @param array $jwks The JSON Web Keys of the identity provider
     * @throws ServiceException if the algorithm is not supported or no suitable key exists
     * @see https://tools.ietf.org/html/rfc7517
     */
    public function hasValidSignature(array $jwks): bool
    {
        $algorithm = $this->header['alg'];
        if (!in_array($algorithm, self::SUPPORTED_ALGORITHMS, true)) {
            throw new ServiceException(sprintf('Unsupported JWT signature type %s.', json_encode($algorithm)), 1559213623);
        }

        $hashType = 'sha' . substr($algorithm, 2);
        foreach ($this->getMatchingKeysForJws($jwks, $algorithm, $this->header['kid'] ?? null) as $jwk) {
            if ($this->verifyRsaJwtSignature($hashType, $jwk)) {
                return true;
            }
        }
        return false;
    }

    /**
     * A token without an expiration time counts as expired, because OpenID Connect requires the "exp" claim.
     */
    public function isExpiredAt(DateTimeInterface $now): bool
    {
        if (!$this->parsedJwt->claims()->has(RegisteredClaims::EXPIRATION_TIME)) {
            return true;
        }
        return $this->parsedJwt->isExpired($now);
    }

    /**
     * Checks if the token was issued ("iat") or becomes valid ("nbf") only after the given time
     */
    public function isNotYetValidAt(DateTimeInterface $now): bool
    {
        $claims = $this->parsedJwt->claims();
        if ($claims->has(RegisteredClaims::ISSUED_AT) && !$this->parsedJwt->hasBeenIssuedBefore($now)) {
            return true;
        }
        return $claims->has(RegisteredClaims::NOT_BEFORE) && !$this->parsedJwt->isMinimumTimeBefore($now);
    }

    public function isIssuedBy(string $issuer): bool
    {
        return ($this->values['iss'] ?? null) === $issuer;
    }

    /**
     * Checks if the identity token's "scope" value contains the given identifier
     */
    public function scopeContains(string $scopeIdentifier): bool
    {
        $scopeIdentifiers = Arrays::trimExplode(',', $this->values['scope'] ?? '');
        return in_array($scopeIdentifier, $scopeIdentifiers, true);
    }

    /**
     * Checks if the identity token's "aud" value contains the given audience
     *
     * The "aud" claim may be a single string or an array of strings (RFC 7519, section 4.1.3).
     */
    public function audienceContains(string $audience): bool
    {
        $audiences = $this->values['aud'] ?? [];
        if (is_string($audiences)) {
            $audiences = [$audiences];
        }
        return is_array($audiences) && array_is_list($audiences) && in_array($audience, $audiences, true);
    }

    /**
     * Verifies the signature of this token using the given JSON web key and hash type, for example "sha256"
     */
    private function verifyRsaJwtSignature(string $hashType, array $jwk): bool
    {
        try {
            $key = PublicKeyLoader::load([
                'e' => new BigInteger(self::base64UrlDecode($jwk['e']), 256),
                'n' => new BigInteger(self::base64UrlDecode($jwk['n']), 256)
            ]);
        } catch (NoKeyLoadedException) {
            return false;
        }
        return $key
            ->withHash($hashType)
            ->withPadding(RSA::SIGNATURE_PKCS1)
            ->verify($this->payload, $this->signature);
    }

    /**
     * Returns the keys of the given JSON Web Key Set which may have been used for signing this token
     *
     * @return array[]
     * @throws ServiceException
     */
    private function getMatchingKeysForJws(array $keys, string $algorithm, ?string $keyIdentifier): array
    {
        $matchingKeys = array_values(array_filter(
            $keys,
            static fn (mixed $key): bool => self::isKeySuitableForAlgorithm($key, $algorithm)
                && ($keyIdentifier === null || ($key['kid'] ?? null) === $keyIdentifier)
        ));
        if ($matchingKeys !== []) {
            return $matchingKeys;
        }
        if ($keyIdentifier !== null) {
            throw new ServiceException(sprintf('Failed finding a matching JSON Web Key using algorithm %s for key identifier %s.', $algorithm, json_encode($keyIdentifier)), 1559213482);
        }
        throw new ServiceException(sprintf('Failed finding a matching JSON Web Key using algorithm %s.', $algorithm), 1559213507);
    }

    /**
     * A key is suitable if it is an RSA key meant for verifying signatures and does not declare a different algorithm
     *
     * @see https://tools.ietf.org/html/rfc7517#section-4
     */
    private static function isKeySuitableForAlgorithm(mixed $key, string $algorithm): bool
    {
        if (!is_array($key) || ($key['kty'] ?? null) !== 'RSA' || !is_string($key['n'] ?? null) || !is_string($key['e'] ?? null)) {
            return false;
        }
        if (isset($key['use']) && $key['use'] !== 'sig') {
            return false;
        }
        if (isset($key['key_ops']) && (!is_array($key['key_ops']) || !in_array('verify', $key['key_ops'], true))) {
            return false;
        }
        return !isset($key['alg']) || $key['alg'] === $algorithm;
    }

    /**
     * Decode Base64URL-encoded data
     */
    private static function base64UrlDecode(string $base64UrlEncodedString): string
    {
        $padding = strlen($base64UrlEncodedString) % 4;
        if ($padding > 0) {
            $base64UrlEncodedString .= str_repeat('=', 4 - $padding);
        }
        return base64_decode(strtr($base64UrlEncodedString, '-_', '+/'));
    }

    public function __toString(): string
    {
        return $this->asJwt();
    }
}
