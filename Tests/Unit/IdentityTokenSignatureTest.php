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

use InvalidArgumentException;
use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\RSA\PrivateKey;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

class IdentityTokenSignatureTest extends TestCase
{
    private static PrivateKey $signingKey;

    private static PrivateKey $otherKey;

    public static function setUpBeforeClass(): void
    {
        self::$signingKey = RSA::createKey(2048);
        self::$otherKey = RSA::createKey(2048);
    }

    public static function rsaAlgorithms(): array
    {
        return [
            'RS256' => ['RS256'],
            'RS384' => ['RS384'],
            'RS512' => ['RS512'],
        ];
    }

    #[Test]
    #[DataProvider('rsaAlgorithms')]
    public function hasValidSignatureAcceptsTokenSignedWithMatchingKey(string $algorithm): void
    {
        $identityToken = IdentityToken::fromJwt(self::createSignedJwt($algorithm, 'key-1', self::$signingKey));

        static::assertTrue($identityToken->hasValidSignature([self::createJwk(self::$signingKey, 'key-1')]));
    }

    #[Test]
    public function hasValidSignatureRejectsTamperedPayload(): void
    {
        [$header, , $signature] = explode('.', self::createSignedJwt('RS256', 'key-1', self::$signingKey));
        $tamperedClaims = self::base64UrlEncode(json_encode(['iss' => 'https://id.example.com', 'sub' => 'someone-else', 'exp' => time() + 3600]));
        $identityToken = IdentityToken::fromJwt($header . '.' . $tamperedClaims . '.' . $signature);

        static::assertFalse($identityToken->hasValidSignature([self::createJwk(self::$signingKey, 'key-1')]));
    }

    #[Test]
    public function hasValidSignatureRejectsTokenSignedWithDifferentKey(): void
    {
        $identityToken = IdentityToken::fromJwt(self::createSignedJwt('RS256', 'key-1', self::$otherKey));

        static::assertFalse($identityToken->hasValidSignature([self::createJwk(self::$signingKey, 'key-1')]));
    }

    #[Test]
    public function hasValidSignatureSelectsKeyByKeyIdentifier(): void
    {
        $identityToken = IdentityToken::fromJwt(self::createSignedJwt('RS256', 'key-2', self::$signingKey));
        $jwks = [
            self::createJwk(self::$otherKey, 'key-1'),
            self::createJwk(self::$signingKey, 'key-2'),
        ];

        static::assertTrue($identityToken->hasValidSignature($jwks));
    }

    #[Test]
    public function hasValidSignatureIgnoresKeysWithoutIdentifierIfTokenNamesOne(): void
    {
        $identityToken = IdentityToken::fromJwt(self::createSignedJwt('RS256', 'key-1', self::$signingKey));
        $keyWithoutIdentifier = self::createJwk(self::$signingKey, 'unused');
        unset($keyWithoutIdentifier['kid']);
        $jwks = [
            $keyWithoutIdentifier,
            self::createJwk(self::$otherKey, 'key-1'),
        ];

        static::assertFalse($identityToken->hasValidSignature($jwks));
    }

    #[Test]
    public function hasValidSignatureTriesAllSuitableKeysIfTokenNamesNoKeyIdentifier(): void
    {
        $identityToken = IdentityToken::fromJwt(self::createSignedJwt('RS256', null, self::$signingKey));
        $jwks = [
            self::createJwk(self::$otherKey, 'key-1'),
            self::createJwk(self::$signingKey, 'key-2'),
        ];

        static::assertTrue($identityToken->hasValidSignature($jwks));
    }

    #[Test]
    public function hasValidSignatureThrowsExceptionIfNoKeyMatchesKeyIdentifier(): void
    {
        $identityToken = IdentityToken::fromJwt(self::createSignedJwt('RS256', 'unknown-key', self::$signingKey));

        $this->expectException(ServiceException::class);
        $this->expectExceptionCode(1559213482);
        $identityToken->hasValidSignature([self::createJwk(self::$signingKey, 'key-1')]);
    }

    #[Test]
    public function hasValidSignatureAcceptsKeyWithoutUsageAndAlgorithm(): void
    {
        $identityToken = IdentityToken::fromJwt(self::createSignedJwt('RS256', 'key-1', self::$signingKey));
        $jwk = self::createJwk(self::$signingKey, 'key-1');
        unset($jwk['use'], $jwk['alg']);

        static::assertTrue($identityToken->hasValidSignature([$jwk]));
    }

    public static function unsuitableKeyProperties(): array
    {
        return [
            'meant for encryption' => [['use' => 'enc']],
            'without verify operation' => [['key_ops' => ['encrypt']]],
            'for another algorithm' => [['alg' => 'RS512']],
            'of another key type' => [['kty' => 'EC']],
            'without modulus' => [['n' => null]],
        ];
    }

    #[Test]
    #[DataProvider('unsuitableKeyProperties')]
    public function hasValidSignatureIgnoresUnsuitableKeys(array $keyProperties): void
    {
        $identityToken = IdentityToken::fromJwt(self::createSignedJwt('RS256', 'key-1', self::$signingKey));
        $jwk = array_filter(array_merge(self::createJwk(self::$signingKey, 'key-1'), $keyProperties), static fn (mixed $value): bool => $value !== null);

        $this->expectException(ServiceException::class);
        $this->expectExceptionCode(1559213482);
        $identityToken->hasValidSignature([$jwk, 'not a key']);
    }

    public static function unsupportedAlgorithms(): array
    {
        return [
            'none' => ['none'],
            'HMAC' => ['HS256'],
            'ECDSA' => ['ES256'],
        ];
    }

    #[Test]
    #[DataProvider('unsupportedAlgorithms')]
    public function hasValidSignatureThrowsExceptionForUnsupportedAlgorithms(string $algorithm): void
    {
        [, $claims, $signature] = explode('.', self::createSignedJwt('RS256', 'key-1', self::$signingKey));
        $header = self::base64UrlEncode(json_encode(['typ' => 'JWT', 'alg' => $algorithm, 'kid' => 'key-1']));
        $identityToken = IdentityToken::fromJwt($header . '.' . $claims . '.' . $signature);

        $this->expectException(ServiceException::class);
        $this->expectExceptionCode(1559213623);
        $identityToken->hasValidSignature([self::createJwk(self::$signingKey, 'key-1')]);
    }

    public static function invalidHeaders(): array
    {
        return [
            'algorithm is not a string' => [['alg' => ['RS256']], 1789122172],
            'key identifier is not a string' => [['alg' => 'RS256', 'kid' => ['key-1']], 1789122173],
        ];
    }

    #[Test]
    #[DataProvider('invalidHeaders')]
    public function fromJwtRejectsInvalidHeaderValues(array $header, int $expectedExceptionCode): void
    {
        [, $claims, $signature] = explode('.', self::createSignedJwt('RS256', 'key-1', self::$signingKey));

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionCode($expectedExceptionCode);
        IdentityToken::fromJwt(self::base64UrlEncode(json_encode($header)) . '.' . $claims . '.' . $signature);
    }

    private static function createSignedJwt(string $algorithm, ?string $keyIdentifier, PrivateKey $privateKey): string
    {
        $headerValues = ['typ' => 'JWT', 'alg' => $algorithm];
        if ($keyIdentifier !== null) {
            $headerValues['kid'] = $keyIdentifier;
        }
        $header = self::base64UrlEncode(json_encode($headerValues));
        $claims = self::base64UrlEncode(json_encode(['iss' => 'https://id.example.com', 'sub' => 'subject', 'exp' => time() + 3600]));
        $signature = $privateKey
            ->withHash('sha' . substr($algorithm, 2))
            ->withPadding(RSA::SIGNATURE_PKCS1)
            ->sign($header . '.' . $claims);

        return $header . '.' . $claims . '.' . self::base64UrlEncode($signature);
    }

    private static function createJwk(PrivateKey $privateKey, string $keyIdentifier): array
    {
        $jwks = json_decode($privateKey->getPublicKey()->toString('JWK'), true, 512, JSON_THROW_ON_ERROR);
        return array_merge($jwks['keys'][0], ['kid' => $keyIdentifier, 'use' => 'sig']);
    }

    private static function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
}
