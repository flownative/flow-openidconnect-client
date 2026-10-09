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

use Flownative\OpenIdConnect\Client\Tests\Unit\Fixtures\OpenIdConnectClientFixture;
use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\RequestOptions;
use Neos\Cache\Backend\TransientMemoryBackend;
use Neos\Cache\Frontend\VariableFrontend;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use ReflectionMethod;
use RuntimeException;

class HttpClientFactoryTest extends TestCase
{
    #[Test]
    public function createUsesDefaultTimeouts(): void
    {
        $factory = new HttpClientFactory();
        $factory->initializeObject();
        $client = $factory->create();

        static::assertInstanceOf(Client::class, $client);
        static::assertSame(5.0, $client->getConfig(RequestOptions::CONNECT_TIMEOUT));
        static::assertSame(10.0, $client->getConfig(RequestOptions::TIMEOUT));
    }

    #[Test]
    public function createUsesConfiguredTimeouts(): void
    {
        $factory = new HttpClientFactory();
        OpenIdConnectClientFixture::inject($factory, 'settings', ['connectTimeout' => 2, 'timeout' => 3.5]);
        $factory->initializeObject();

        $client = $factory->create();

        static::assertSame(2.0, $client->getConfig(RequestOptions::CONNECT_TIMEOUT));
        static::assertSame(3.5, $client->getConfig(RequestOptions::TIMEOUT));
    }

    public static function invalidTimeouts(): array
    {
        return [
            'zero, which Guzzle reads as no limit' => [['timeout' => 0]],
            'negative' => [['connectTimeout' => -1]],
            'not a number' => [['timeout' => '10']],
        ];
    }

    #[Test]
    #[DataProvider('invalidTimeouts')]
    public function initializeObjectRejectsTimeoutWhichIsNoPositiveNumber(array $settings): void
    {
        $factory = new HttpClientFactory();
        OpenIdConnectClientFixture::inject($factory, 'settings', $settings);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionCode(1791540877);
        $factory->initializeObject();
    }

    #[Test]
    public function openIdConnectClientRetrievesKeysWithTheClientOfTheFactory(): void
    {
        $httpClient = $this->createMock(ClientInterface::class);
        $httpClient->expects($this->once())->method('request')->with('GET', OpenIdConnectClientFixture::JWKS_URI)->willReturn(new Response(200, [], json_encode(['keys' => []], JSON_THROW_ON_ERROR)));
        $factory = $this->createStub(HttpClientFactoryInterface::class);
        $factory->method('create')->willReturn($httpClient);

        $jwksCache = new VariableFrontend('jwks', new TransientMemoryBackend());
        $jwksCache->initializeObject();
        $client = OpenIdConnectClientFixture::createClient($this->createStub(OAuthClient::class), OpenIdConnectClientFixture::createHashService(), $this->createStub(LoggerInterface::class));
        OpenIdConnectClientFixture::inject($client, 'httpClientFactory', $factory);
        OpenIdConnectClientFixture::inject($client, 'jwksCache', $jwksCache);

        static::assertSame([], $client->getJwks());
    }

    #[Test]
    public function oAuthClientCreatesItsHttpClientWithTheFactory(): void
    {
        $httpClient = $this->createStub(ClientInterface::class);
        $factory = $this->createStub(HttpClientFactoryInterface::class);
        $factory->method('create')->willReturn($httpClient);
        $oAuthClient = new OAuthClient(OpenIdConnectClientFixture::SERVICE_NAME);
        OpenIdConnectClientFixture::inject($oAuthClient, 'httpClientFactory', $factory);

        static::assertSame($httpClient, (new ReflectionMethod($oAuthClient, 'createHttpClient'))->invoke($oAuthClient));
    }
}
