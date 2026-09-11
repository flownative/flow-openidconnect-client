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

use Flownative\OpenIdConnect\Client\OAuthClient;
use Flownative\OpenIdConnect\Client\OpenIdConnectClient;
use GuzzleHttp\Client as HttpClient;
use Neos\Cache\Backend\TransientMemoryBackend;
use Neos\Cache\Frontend\VariableFrontend;
use Neos\Flow\Security\Cryptography\HashService;
use Psr\Log\LoggerInterface;
use ReflectionProperty;

/**
 * Builds OpenID Connect clients for unit tests, without Flow's dependency injection
 *
 * The client uses in-memory caches, so a test can provide the JSON Web Key Set up front
 * instead of mocking HTTP requests.
 */
final class OpenIdConnectClientFixture
{
    public const string SERVICE_NAME = 'test';
    public const string ISSUER = 'https://id.example.com/';
    public const string JWKS_URI = 'https://id.example.com/.well-known/jwks.json';
    public const string TOKEN_ENDPOINT = 'https://id.example.com/oauth/token';
    public const string CLIENT_ID = 'the-client';
    public const string CLIENT_SECRET = 'the-secret';

    /**
     * @param array $serviceOptions Options which replace the default options of the test service
     */
    public static function createClient(OAuthClient $oAuthClient, HashService $hashService, LoggerInterface $logger, array $jwks = [], ?HttpClient $httpClient = null, array $serviceOptions = []): OpenIdConnectClient
    {
        $discoveryCache = new VariableFrontend('discovery', new TransientMemoryBackend());
        $discoveryCache->initializeObject();
        $jwksCache = new VariableFrontend('jwks', new TransientMemoryBackend());
        $jwksCache->initializeObject();
        if ($jwks !== []) {
            $jwksCache->set(sha1(self::JWKS_URI), $jwks);
        }

        $client = new OpenIdConnectClient(self::SERVICE_NAME);
        self::inject($client, 'settings', [
            'services' => [
                self::SERVICE_NAME => [
                    'options' => array_merge([
                        'issuer' => self::ISSUER,
                        'jwksUri' => self::JWKS_URI,
                        'tokenEndpoint' => self::TOKEN_ENDPOINT,
                        'clientId' => self::CLIENT_ID,
                        'clientSecret' => self::CLIENT_SECRET,
                    ], $serviceOptions)
                ]
            ]
        ]);
        self::inject($client, 'discoveryCache', $discoveryCache);
        self::inject($client, 'jwksCache', $jwksCache);
        self::inject($client, 'logger', $logger);
        self::inject($client, 'hashService', $hashService);
        if ($httpClient !== null) {
            self::inject($client, 'httpClient', $httpClient);
        }
        $client->initializeObject();

        // initializeObject() creates its own OAuth client, so the test double is injected afterwards.
        self::inject($client, 'oAuthClient', $oAuthClient);
        return $client;
    }

    public static function createHashService(): HashService
    {
        $hashService = new HashService();
        // Flow 9.0 does not accept the encryption key as a setting, so it is set on the property.
        self::inject($hashService, 'encryptionKey', 'test-encryption-key');
        return $hashService;
    }

    public static function inject(object $target, string $propertyName, mixed $value): void
    {
        (new ReflectionProperty($target, $propertyName))->setValue($target, $value);
    }
}
