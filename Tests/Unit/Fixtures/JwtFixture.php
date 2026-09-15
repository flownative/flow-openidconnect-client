<?php
declare(strict_types=1);

namespace Flownative\OpenIdConnect\Client\Tests\Unit\Fixtures;

/*
 * This file is part of the Flownative.OpenIdConnect.Client package.
 *
 * (c) Robert Lemke, Flownative GmbH - www.flownative.com
 *
 * This package is Open Source Software. For the full copyright and license
 * information, please view the LICENSE file which was distributed with this
 * source code.
 */

use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\RSA\PrivateKey;

/**
 * Creates RS256-signed JWTs and the matching JSON Web Key Set for unit tests
 *
 * Each key pair is generated once per test run.
 */
final class JwtFixture
{
    public const string KEY_IDENTIFIER = 'key-1';
    public const string ROTATED_KEY_IDENTIFIER = 'key-2'; # a key which the identity provider published after the key set was cached

    /**
     * @var array<string, PrivateKey>
     */
    private static array $signingKeys = [];

    public static function createSignedJwt(array $claims, string $keyIdentifier = self::KEY_IDENTIFIER): string
    {
        $header = self::base64UrlEncode(json_encode(['typ' => 'JWT', 'alg' => 'RS256', 'kid' => $keyIdentifier], JSON_THROW_ON_ERROR));
        $payload = self::base64UrlEncode(json_encode($claims, JSON_THROW_ON_ERROR));
        $signature = self::signingKey($keyIdentifier)
            ->withHash('sha256')
            ->withPadding(RSA::SIGNATURE_PKCS1)
            ->sign($header . '.' . $payload);

        return $header . '.' . $payload . '.' . self::base64UrlEncode($signature);
    }

    public static function createJwks(string ...$keyIdentifiers): array
    {
        $jwks = [];
        foreach ($keyIdentifiers === [] ? [self::KEY_IDENTIFIER] : $keyIdentifiers as $keyIdentifier) {
            $publicKey = json_decode(self::signingKey($keyIdentifier)->getPublicKey()->toString('JWK'), true, 512, JSON_THROW_ON_ERROR);
            $jwks[] = array_merge($publicKey['keys'][0], ['kid' => $keyIdentifier, 'use' => 'sig', 'alg' => 'RS256']);
        }
        return $jwks;
    }

    private static function signingKey(string $keyIdentifier): PrivateKey
    {
        return self::$signingKeys[$keyIdentifier] ??= RSA::createKey(2048);
    }

    private static function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
}
