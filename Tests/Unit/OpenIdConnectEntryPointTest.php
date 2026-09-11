<?php
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

use Flownative\OAuth2\Client\OAuthClientException;
use Flownative\OpenIdConnect\Client\Authentication\OpenIdConnectEntryPoint;
use Flownative\OpenIdConnect\Client\Authentication\OpenIdConnectToken;
use Flownative\OpenIdConnect\Client\Authentication\TokenArguments;
use Flownative\OpenIdConnect\Client\Tests\Unit\Fixtures\OpenIdConnectClientFixture;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\ServerRequest;
use GuzzleHttp\Psr7\Uri;
use Neos\Flow\Security\Cryptography\HashService;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\UriInterface;
use Psr\Log\LoggerInterface;

class OpenIdConnectEntryPointTest extends TestCase
{
    private const string AUTHORIZATION_URI = 'https://id.example.com/authorize?state=abc&client_id=the-client';

    public static function invalidOptions(): array
    {
        return [
            'missing service name' => [[], 1559898606],
            'scope is not a string' => [['serviceName' => 'test', 'scope' => ['profile']], 1560259102],
            'requestRefreshToken is not a boolean' => [['serviceName' => 'test', 'requestRefreshToken' => 'yes'], 1789108753],
        ];
    }

    #[Test]
    #[DataProvider('invalidOptions')]
    public function startAuthenticationRejectsInvalidOptions(array $options, int $expectedExceptionCode): void
    {
        $entryPoint = new OpenIdConnectEntryPoint();
        $entryPoint->setOptions($options);

        $this->expectException(ConfigurationException::class);
        $this->expectExceptionCode($expectedExceptionCode);
        $entryPoint->startAuthentication(new ServerRequest('GET', 'https://www.example.com/'), new Response());
    }

    #[Test]
    public function startAuthenticationRedirectsToAuthorizationEndpoint(): void
    {
        $oAuthClient = $this->createStub(OAuthClient::class);
        $oAuthClient->method('startAuthorization')->willReturn(new Uri(self::AUTHORIZATION_URI));
        $entryPoint = $this->createEntryPoint($oAuthClient, ['serviceName' => 'test']);

        $response = $entryPoint->startAuthentication(new ServerRequest('GET', 'https://www.example.com/secure'), new Response());

        static::assertSame(303, $response->getStatusCode());
        static::assertSame(self::AUTHORIZATION_URI, $response->getHeaderLine('Location'));
        static::assertStringContainsString('content="0;url=https://id.example.com/authorize?state=abc&amp;client_id=the-client"', (string)$response->getBody());
    }

    #[Test]
    public function startAuthenticationReturnsToRequestedUriWithSignedServiceName(): void
    {
        $hashService = OpenIdConnectClientFixture::createHashService();
        $returnToUri = null;
        $scope = null;
        $oAuthClient = $this->createStub(OAuthClient::class);
        $oAuthClient->method('startAuthorization')->willReturnCallback(
            function (string $clientId, string $clientSecret, UriInterface $givenReturnToUri, string $givenScope) use (&$returnToUri, &$scope): UriInterface {
                $returnToUri = $givenReturnToUri;
                $scope = $givenScope;
                return new Uri(self::AUTHORIZATION_URI);
            }
        );
        $entryPoint = $this->createEntryPoint($oAuthClient, ['serviceName' => 'test', 'scope' => 'profile email'], $hashService);

        $entryPoint->startAuthentication(new ServerRequest('GET', 'https://www.example.com/secure?page=2'), new Response());

        parse_str($returnToUri->getQuery(), $queryParameters);
        static::assertSame('/secure', $returnToUri->getPath());
        static::assertSame('2', $queryParameters['page']);
        static::assertSame('test', TokenArguments::fromSignedString($queryParameters[OpenIdConnectToken::OIDC_PARAMETER_NAME], $hashService)[TokenArguments::SERVICE_NAME]);
        static::assertSame('profile email openid offline_access', $scope);
    }

    #[Test]
    public function startAuthenticationOmitsOfflineAccessIfRefreshTokenIsNotRequested(): void
    {
        $scope = null;
        $oAuthClient = $this->createStub(OAuthClient::class);
        $oAuthClient->method('startAuthorization')->willReturnCallback(
            function (string $clientId, string $clientSecret, UriInterface $returnToUri, string $givenScope) use (&$scope): UriInterface {
                $scope = $givenScope;
                return new Uri(self::AUTHORIZATION_URI);
            }
        );
        $entryPoint = $this->createEntryPoint($oAuthClient, ['serviceName' => 'test', 'scope' => 'profile', 'requestRefreshToken' => false]);

        $entryPoint->startAuthentication(new ServerRequest('GET', 'https://www.example.com/'), new Response());

        static::assertSame('profile openid', $scope);
    }

    #[Test]
    public function startAuthenticationReturnsGivenResponseIfAuthorizationCannotBeStarted(): void
    {
        $oAuthClient = $this->createStub(OAuthClient::class);
        $oAuthClient->method('startAuthorization')->willThrowException(new OAuthClientException('Failed storing authorization', 1568727133));
        $entryPoint = $this->createEntryPoint($oAuthClient, ['serviceName' => 'test']);
        $originalResponse = new Response();

        static::assertSame($originalResponse, $entryPoint->startAuthentication(new ServerRequest('GET', 'https://www.example.com/'), $originalResponse));
    }

    private function createEntryPoint(OAuthClient $oAuthClient, array $options, ?HashService $hashService = null): OpenIdConnectEntryPoint
    {
        $logger = $this->createStub(LoggerInterface::class);
        $client = OpenIdConnectClientFixture::createClient($oAuthClient, $hashService ?? OpenIdConnectClientFixture::createHashService(), $logger);
        $clientFactory = $this->createStub(OpenIdConnectClientFactory::class);
        $clientFactory->method('create')->willReturn($client);

        $entryPoint = new OpenIdConnectEntryPoint();
        $entryPoint->setOptions($options);
        OpenIdConnectClientFixture::inject($entryPoint, 'logger', $logger);
        OpenIdConnectClientFixture::inject($entryPoint, 'openIdConnectClientFactory', $clientFactory);
        return $entryPoint;
    }
}
