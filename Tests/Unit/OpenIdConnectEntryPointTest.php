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

use Flownative\OAuth2\Client\OAuthClientException;
use Flownative\OpenIdConnect\Client\Authentication\Nonce;
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
        static::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
    }

    public static function requestsWhichDoNotNavigate(): array
    {
        return [
            'bearer token' => [['Authorization' => 'Bearer some-token']],
            'XMLHttpRequest' => [['X-Requested-With' => 'XMLHttpRequest']],
            'fetch in CORS mode' => [['Sec-Fetch-Mode' => 'cors']],
            'fetch in same-origin mode' => [['Sec-Fetch-Mode' => 'same-origin']],
            'image or script' => [['Sec-Fetch-Mode' => 'no-cors']],
        ];
    }

    #[Test]
    #[DataProvider('requestsWhichDoNotNavigate')]
    public function startAuthenticationAnswersWithStatus401IfRequestDoesNotNavigate(array $headers): void
    {
        $oAuthClient = $this->createMock(OAuthClient::class);
        $oAuthClient->expects($this->never())->method('startAuthorization');
        $entryPoint = $this->createEntryPoint($oAuthClient, ['serviceName' => 'test']);

        $response = $entryPoint->startAuthentication(new ServerRequest('GET', 'https://www.example.com/api', $headers), new Response());

        static::assertSame(401, $response->getStatusCode());
        static::assertSame('Bearer', $response->getHeaderLine('WWW-Authenticate'));
        static::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
        static::assertFalse($response->hasHeader('Set-Cookie'));
    }

    public static function requestsWhichNavigate(): array
    {
        return [
            'navigation' => [['Sec-Fetch-Mode' => 'navigate']],
            'browser without fetch metadata' => [[]],
            'navigation with basic authentication' => [['Sec-Fetch-Mode' => 'navigate', 'Authorization' => 'Basic dXNlcjpwYXNzd29yZA==']],
        ];
    }

    #[Test]
    #[DataProvider('requestsWhichNavigate')]
    public function startAuthenticationRedirectsIfRequestNavigates(array $headers): void
    {
        $oAuthClient = $this->createStub(OAuthClient::class);
        $oAuthClient->method('startAuthorization')->willReturn(new Uri(self::AUTHORIZATION_URI));
        $entryPoint = $this->createEntryPoint($oAuthClient, ['serviceName' => 'test']);

        $response = $entryPoint->startAuthentication(new ServerRequest('GET', 'https://www.example.com/secure', $headers), new Response());

        static::assertSame(303, $response->getStatusCode());
        static::assertSame(self::AUTHORIZATION_URI, $response->getHeaderLine('Location'));
    }

    #[Test]
    public function startAuthenticationBindsAuthorizationToBrowserWithNonceCookie(): void
    {
        $authorizationParameters = [];
        $oAuthClient = $this->createStub(OAuthClient::class);
        $oAuthClient->method('startAuthorization')->willReturnCallback(
            function (string $clientId, string $clientSecret, UriInterface $returnToUri, string $scope, array $givenAuthorizationParameters) use (&$authorizationParameters): UriInterface {
                $authorizationParameters = $givenAuthorizationParameters;
                return new Uri(self::AUTHORIZATION_URI);
            }
        );
        $entryPoint = $this->createEntryPoint($oAuthClient, ['serviceName' => 'test']);

        $response = $entryPoint->startAuthentication(new ServerRequest('GET', 'https://www.example.com/secure'), new Response());

        static::assertMatchesRegularExpression('/^(__Host-flownative_oidc_nonce_[0-9a-f]{16})=([0-9a-f]{64}); Max-Age=3600; Path=\/; Secure; HttpOnly; SameSite=lax$/', $response->getHeaderLine('Set-Cookie'));
        preg_match('/^([^=]+)=([^;]+);/', $response->getHeaderLine('Set-Cookie'), $matches);
        static::assertTrue(Nonce::isBoundToCookies($authorizationParameters['nonce'], [$matches[1] => $matches[2]], CookieSettings::fromMiddlewareSettings([])));
    }

    public static function insecureCookieSettings(): array
    {
        return [
            'cookie.secure' => [['cookie' => ['secure' => false]]],
            'deprecated secureCookie' => [['secureCookie' => false, 'cookie' => ['secure' => true]]],
        ];
    }

    #[Test]
    #[DataProvider('insecureCookieSettings')]
    public function startAuthenticationSetsNonceCookieWithoutSecureFlagIfConfigured(array $middlewareSettings): void
    {
        $oAuthClient = $this->createStub(OAuthClient::class);
        $oAuthClient->method('startAuthorization')->willReturn(new Uri(self::AUTHORIZATION_URI));
        $entryPoint = $this->createEntryPoint($oAuthClient, ['serviceName' => 'test']);
        OpenIdConnectClientFixture::inject($entryPoint, 'middlewareSettings', $middlewareSettings);

        $response = $entryPoint->startAuthentication(new ServerRequest('GET', 'http://localhost/secure'), new Response());

        static::assertStringStartsWith('flownative_oidc_nonce_', $response->getHeaderLine('Set-Cookie'));
        static::assertStringEndsWith('; Max-Age=3600; Path=/; HttpOnly; SameSite=lax', $response->getHeaderLine('Set-Cookie'));
    }

    #[Test]
    public function startAuthenticationReturnsToRequestedUriWithSignedServiceNameAndNonce(): void
    {
        $hashService = OpenIdConnectClientFixture::createHashService();
        $returnToUri = null;
        $scope = null;
        $authorizationParameters = [];
        $oAuthClient = $this->createStub(OAuthClient::class);
        $oAuthClient->method('startAuthorization')->willReturnCallback(
            function (string $clientId, string $clientSecret, UriInterface $givenReturnToUri, string $givenScope, array $givenAuthorizationParameters) use (&$returnToUri, &$scope, &$authorizationParameters): UriInterface {
                $returnToUri = $givenReturnToUri;
                $scope = $givenScope;
                $authorizationParameters = $givenAuthorizationParameters;
                return new Uri(self::AUTHORIZATION_URI);
            }
        );
        $entryPoint = $this->createEntryPoint($oAuthClient, ['serviceName' => 'test', 'scope' => 'profile email'], $hashService);

        $entryPoint->startAuthentication(new ServerRequest('GET', 'https://www.example.com/secure?page=2'), new Response());

        parse_str($returnToUri->getQuery(), $queryParameters);
        $tokenArguments = TokenArguments::fromSignedString($queryParameters[OpenIdConnectToken::OIDC_PARAMETER_NAME], $hashService);
        static::assertSame('/secure', $returnToUri->getPath());
        static::assertSame('2', $queryParameters['page']);
        static::assertSame('test', $tokenArguments[TokenArguments::SERVICE_NAME]);
        static::assertSame($authorizationParameters['nonce'], $tokenArguments[TokenArguments::NONCE]);
        static::assertSame('profile email openid offline_access', $scope);
    }

    #[Test]
    public function startAuthenticationRemovesParametersOfRejectedReturnFromReturnUri(): void
    {
        $returnToUri = null;
        $oAuthClient = $this->createStub(OAuthClient::class);
        $oAuthClient->method('startAuthorization')->willReturnCallback(
            function (string $clientId, string $clientSecret, UriInterface $givenReturnToUri) use (&$returnToUri): UriInterface {
                $returnToUri = $givenReturnToUri;
                return new Uri(self::AUTHORIZATION_URI);
            }
        );
        $authorizationIdQueryParameterName = OAuthClient::generateAuthorizationIdQueryParameterName(OAuthClient::SERVICE_TYPE);
        $entryPoint = $this->createEntryPoint($oAuthClient, ['serviceName' => 'test']);

        $entryPoint->startAuthentication(new ServerRequest('GET', 'https://www.example.com/secure?page=2&' . OpenIdConnectToken::OIDC_PARAMETER_NAME . '=stale&' . $authorizationIdQueryParameterName . '=stale-id'), new Response());

        parse_str($returnToUri->getQuery(), $queryParameters);
        static::assertSame(['page', OpenIdConnectToken::OIDC_PARAMETER_NAME], array_keys($queryParameters));
        static::assertNotSame('stale', $queryParameters[OpenIdConnectToken::OIDC_PARAMETER_NAME]);
    }

    public static function pendingLogins(): array
    {
        return [
            'below the limit' => [4, 0],
            'at the limit' => [5, 5],
        ];
    }

    #[Test]
    #[DataProvider('pendingLogins')]
    public function startAuthenticationRemovesNonceCookiesOfPendingLoginsAtTheLimit(int $numberOfPendingLogins, int $expectedNumberOfRemovedCookies): void
    {
        $cookies = ['flownative_oidc_jwt' => 'unrelated'];
        for ($i = 0; $i < $numberOfPendingLogins; $i++) {
            $cookie = Nonce::generate()->createCookie(CookieSettings::fromMiddlewareSettings([]));
            $cookies[$cookie->getName()] = $cookie->getValue();
        }
        $oAuthClient = $this->createStub(OAuthClient::class);
        $oAuthClient->method('startAuthorization')->willReturn(new Uri(self::AUTHORIZATION_URI));
        $entryPoint = $this->createEntryPoint($oAuthClient, ['serviceName' => 'test']);

        $response = $entryPoint->startAuthentication((new ServerRequest('GET', 'https://www.example.com/secure'))->withCookieParams($cookies), new Response());

        $setCookieHeaders = $response->getHeader('Set-Cookie');
        static::assertCount($expectedNumberOfRemovedCookies + 1, $setCookieHeaders);
        static::assertCount($expectedNumberOfRemovedCookies, array_filter($setCookieHeaders, static fn (string $header): bool => str_contains($header, '=; Expires=Thu, 01-Jan-1970 00:00:01 GMT')));
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
