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
 * The key pair is generated once per test run.
 */
final class JwtFixture
{
    public const string KEY_IDENTIFIER = 'key-1';

    private static ?PrivateKey $signingKey = null;

    public static function createSignedJwt(array $claims): string
    {
        $header = self::base64UrlEncode(json_encode(['typ' => 'JWT', 'alg' => 'RS256', 'kid' => self::KEY_IDENTIFIER], JSON_THROW_ON_ERROR));
        $payload = self::base64UrlEncode(json_encode($claims, JSON_THROW_ON_ERROR));
        $signature = self::signingKey()
            ->withHash('sha256')
            ->withPadding(RSA::SIGNATURE_PKCS1)
            ->sign($header . '.' . $payload);

        return $header . '.' . $payload . '.' . self::base64UrlEncode($signature);
    }

    public static function createJwks(): array
    {
        $jwks = json_decode(self::signingKey()->getPublicKey()->toString('JWK'), true, 512, JSON_THROW_ON_ERROR);
        return [array_merge($jwks['keys'][0], ['kid' => self::KEY_IDENTIFIER, 'use' => 'sig', 'alg' => 'RS256'])];
    }

    private static function signingKey(): PrivateKey
    {
        return self::$signingKey ??= RSA::createKey(2048);
    }

    private static function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
}
