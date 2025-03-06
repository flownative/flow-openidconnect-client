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

use Flownative\OpenIdConnect\Client\Authentication\OpenIdConnectToken;
use Flownative\OpenIdConnect\Client\Http\SetJwtCookieMiddleware;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\Uri;
use Neos\Flow\Security\Account;
use Neos\Flow\Security\Context as SecurityContext;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;

class SetJwtCookieMiddlewareTest extends TestCase
{
    /**
     * header: {
     * "alg": "HS384",
     * "typ": "JWT",
     * "kid": "1Id57j2ybxRQ7hYDPjcrA"
     * }
     * payload: {
     * "name": "Nody McNodeface",
     * "updated_at": "2025-03-03T15:31:15.984Z",
     * "email": "nody@nodeface.invalid",
     * "email_verified": true,
     * "iss": "https://neos.io/",
     * "aud": "dummy-audience",
     * "sub": "nodymcnodeface",
     * "iat": 1741018864,
     * "exp": 1742054864,
     * "sid": "fourteen-chars-and-then-somemore"
     * }
     * key: NTNv7j0TuYARvmNMmWXo6fKvM4o6nv/aUi9ryX38ZH+L1bkrnD1ObOQ8JAUmHCBq7Iy7otZcyAagBLHVKvvYaIpmMuxmARQ97jUVG16Jkpkp1wXOPsrF9zwew6TpczyHkHgX5EuLg2MeBuiT/qJACs1J0apruOOJCg/gOtkjB4c=
     */
    private const JWT_NODY = 'eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6IjFJZDU3ajJ5YnhSUTdoWURQamNyQSJ9.eyJuYW1lIjoiTm9keSBNY05vZGVmYWNlIiwidXBkYXRlZF9hdCI6IjIwMjUtMDMtMDNUMTU6MzE6MTUuOTg0WiIsImVtYWlsIjoibm9keUBub2RlZmFjZS5pbnZhbGlkIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImlzcyI6Imh0dHBzOi8vbmVvcy5pby8iLCJhdWQiOiJkdW1teS1hdWRpZW5jZSIsInN1YiI6Im5vZHltY25vZGVmYWNlIiwiaWF0IjoxNzQxMDE4ODY0LCJleHAiOjE3NDIwNTQ4NjQsInNpZCI6ImZvdXJ0ZWVuLWNoYXJzLWFuZC10aGVuLXNvbWVtb3JlIn0.UD_yaZz1f0IaVAVRED1XqlKAK3Y_500arVJAXawHX7aWoKaotfFS3sD--fwEJ_Pp';
    /**
     * As above, but Jody, not Nody…
     */
    private const JWT_JODY = 'eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6IjFJZDU3ajJ5YnhSUTdoWURQamNyQSJ9.eyJuYW1lIjoiSm9keSBNY05vZGVmYWNlIiwidXBkYXRlZF9hdCI6IjIwMjUtMDMtMDNUMTU6MzE6MTUuOTg0WiIsImVtYWlsIjoiam9keUBub2RlZmFjZS5pbnZhbGlkIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImlzcyI6Imh0dHBzOi8vbmVvcy5pby8iLCJhdWQiOiJkdW1teS1hdWRpZW5jZSIsInN1YiI6ImpvZHltY25vZGVmYWNlIiwiaWF0IjoxNzQxMDE4ODY0LCJleHAiOjE3NDIwNTQ4NjQsInNpZCI6ImZvdXJ0ZWVuLWNoYXJzLWFuZC10aGVuLXNvbWVtb3JlIn0.NN3xy6dvwDuHua0Z3Sj8iJgCwfIMjYeCsE46npxmZ7JoHgbMnN1zSgx5muJOCKSs';

    /**
     * @var SecurityContext|MockObject
     */
    private $mockSecurityContext;

    /**
     * @var LoggerInterface|MockObject
     */
    private $mockLogger;

    /**
     * @var ServerRequestInterface|MockObject
     */
    private $mockRequest;

    /**
     * @var RequestHandlerInterface
     */
    private $mockNextRequestHandler;

    /**
     * @var ResponseInterface|MockObject
     */
    private $mockOriginalResponse;

    public function setUp(): void
    {
        $this->mockSecurityContext = $this->getMockBuilder(SecurityContext::class)->disableOriginalConstructor()->getMock();
        $this->mockLogger = $this->getMockBuilder(LoggerInterface::class)->getMock();
        $this->mockRequest = $this->getMockBuilder(ServerRequestInterface::class)->getMock();
        $this->mockRequest->method('getUri')->willReturn(new Uri('http://localhost'));
        $this->mockOriginalResponse = $this->getMockBuilder(ResponseInterface::class)->getMock();

        $this->mockNextRequestHandler = new class implements RequestHandlerInterface {
            public $originalResponse;
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return $this->originalResponse;
            }
        };
        $this->mockNextRequestHandler->originalResponse = $this->mockOriginalResponse;
    }

    private function getMiddleware(array $options = [], array $authenticationProviderConfiguration = []): SetJwtCookieMiddleware
    {
        $options['disableTrustedProxiesComponentCompatibility'] = true;
        $middleware = new SetJwtCookieMiddleware($options, $authenticationProviderConfiguration, $this->mockSecurityContext, $this->mockLogger);
        $middleware->initializeObject();
        return $middleware;
    }

    /**
     * @test
     */
    public function processReturnsUnalteredResponseOfInnerMiddlewareChainIfSecurityContextIsNotInitialized(): void
    {
        $middleware = $this->getMiddleware();
        $this->mockSecurityContext->expects($this->atLeastOnce())->method('isInitialized')->willReturn(false);
        $response = $middleware->process($this->mockRequest, $this->mockNextRequestHandler);
        self::assertSame($response, $this->mockOriginalResponse);
    }

    /**
     * @test
     */
    public function processReturnsUnalteredResponseOfInnerMiddlewareChainIfNoOidcAuthenticationTokensAreActive(): void
    {
        $middleware = $this->getMiddleware();
        $this->mockSecurityContext->method('isInitialized')->willReturn(true);
        $this->mockSecurityContext->method('getAuthenticationTokensOfType')->willReturn([]);
        $response = $middleware->process($this->mockRequest, $this->mockNextRequestHandler);
        self::assertSame($response, $this->mockOriginalResponse);
    }

    public static function removeJwtCookieDataProvider(): array
    {
        return [
            'no authenticated tokens' => ['options' => [], 'authenticationProviderConfiguration' => [], 'authenticatedTokens' => [], 'activeCookies' => ['flownative_oidc_jwt'], 'expectedCookieHeader' => null],
            'authenticated, no active cookie' => ['options' => [], 'authenticationProviderConfiguration' => [], 'authenticatedTokens' => ['SomeProvider'], 'activeCookies' => [], 'expectedCookieHeader' => null],
            'authenticated, different active cookie name' => ['options' => [], 'authenticationProviderConfiguration' => [], 'authenticatedTokens' => ['SomeProvider'], 'activeCookies' => ['SomeOtherCookie'], 'expectedCookieHeader' => null],

            'authenticated, default options' => ['options' => [], 'authenticationProviderConfiguration' => [], 'authenticatedTokens' => ['SomeProvider'], 'activeCookies' => ['flownative_oidc_jwt'], 'expectedCookieHeader' => 'flownative_oidc_jwt=; Expires=Thu, 01-Jan-1970 00:00:01 GMT; Path=/; Secure; SameSite=lax'],
            'two authenticated tokens, default options' => ['options' => [], 'authenticationProviderConfiguration' => [], 'authenticatedTokens' => ['SomeProvider', 'SomeOtherProvider'], 'activeCookies' => ['flownative_oidc_jwt'], 'expectedCookieHeader' => 'flownative_oidc_jwt=; Expires=Thu, 01-Jan-1970 00:00:01 GMT; Path=/; Secure; SameSite=lax, flownative_oidc_jwt=; Expires=Thu, 01-Jan-1970 00:00:01 GMT; Path=/; Secure; SameSite=lax'],
            'option cookie.name' => ['options' => ['cookie' => ['name' => 'SomeCookieName']], 'authenticationProviderConfiguration' => [], 'authenticatedTokens' => ['SomeProvider'], 'activeCookies' => ['SomeCookieName'], 'expectedCookieHeader' => 'SomeCookieName=; Expires=Thu, 01-Jan-1970 00:00:01 GMT; Path=/; Secure; SameSite=lax'],
            'option cookie.secure' => ['options' => ['cookie' => ['secure' => false]], 'authenticationProviderConfiguration' => [], 'authenticatedTokens' => ['SomeProvider'], 'activeCookies' => ['flownative_oidc_jwt'], 'expectedCookieHeader' => 'flownative_oidc_jwt=; Expires=Thu, 01-Jan-1970 00:00:01 GMT; Path=/; SameSite=lax'],
            'option cookie.httpOnly' => ['options' => ['cookie' => ['httpOnly' => true]], 'authenticationProviderConfiguration' => [], 'authenticatedTokens' => ['SomeProvider'], 'activeCookies' => ['flownative_oidc_jwt'], 'expectedCookieHeader' => 'flownative_oidc_jwt=; Expires=Thu, 01-Jan-1970 00:00:01 GMT; Path=/; Secure; HttpOnly; SameSite=lax'],
            'option cookie.sameSite' => ['options' => ['cookie' => ['sameSite' => 'lax']], 'authenticationProviderConfiguration' => [], 'authenticatedTokens' => ['SomeProvider'], 'activeCookies' => ['flownative_oidc_jwt'], 'expectedCookieHeader' => 'flownative_oidc_jwt=; Expires=Thu, 01-Jan-1970 00:00:01 GMT; Path=/; Secure; SameSite=lax'],

            'option.secureCookie (compat)' => ['options' => ['secureCookie' => false], 'authenticationProviderConfiguration' => [], 'authenticatedTokens' => ['SomeProvider'], 'activeCookies' => ['flownative_oidc_jwt'], 'expectedCookieHeader' => 'flownative_oidc_jwt=; Expires=Thu, 01-Jan-1970 00:00:01 GMT; Path=/; SameSite=lax'],
            'option.secureCookie (compat) overrides cookie.secure' => ['options' => ['secureCookie' => false, 'cookie' => ['secure' => true]], 'authenticationProviderConfiguration' => [], 'authenticatedTokens' => ['SomeProvider'], 'activeCookies' => ['flownative_oidc_jwt'], 'expectedCookieHeader' => 'flownative_oidc_jwt=; Expires=Thu, 01-Jan-1970 00:00:01 GMT; Path=/; SameSite=lax'],

            'option.cookieName (compat)' => ['options' => ['cookieName' => 'SomeCookieName'], 'authenticationProviderConfiguration' => [], 'authenticatedTokens' => ['SomeProvider'], 'activeCookies' => ['SomeCookieName'], 'expectedCookieHeader' => 'SomeCookieName=; Expires=Thu, 01-Jan-1970 00:00:01 GMT; Path=/; Secure; SameSite=lax'],
            'option.cookieName (compat) overrides cookie.name' => ['options' => ['cookieName' => 'SomeCookieName', 'cookie' => ['name' => 'SomeOtherCookieName']], 'authenticationProviderConfiguration' => [], 'authenticatedTokens' => ['SomeProvider'], 'activeCookies' => ['SomeCookieName'], 'expectedCookieHeader' => 'SomeCookieName=; Expires=Thu, 01-Jan-1970 00:00:01 GMT; Path=/; Secure; SameSite=lax'],
            'providerOption.jwtCookieName overrides cookie name options' => ['options' => ['cookieName' => 'SomeCookieName', 'cookie' => ['name' => 'SomeOtherCookieName']], 'authenticationProviderConfiguration' => ['SomeProvider' => ['providerOptions' => ['jwtCookieName' => 'ProviderCookieName']]], 'authenticatedTokens' => ['SomeProvider'], 'activeCookies' => ['SomeCookieName', 'SomeOtherCookieName', 'ProviderCookieName'], 'expectedCookieHeader' => 'ProviderCookieName=; Expires=Thu, 01-Jan-1970 00:00:01 GMT; Path=/; Secure; SameSite=lax'],

            'two authenticated tokens with different cookie names' => [[], 'authenticationProviderConfiguration' => ['SomeProvider' => ['providerOptions' => ['jwtCookieName' => 'ProviderCookieName']]], 'authenticatedTokens' => ['SomeProvider', 'SomeOtherProvider'], 'activeCookies' => ['flownative_oidc_jwt', 'ProviderCookieName'], 'expectedCookieHeader' => 'ProviderCookieName=; Expires=Thu, 01-Jan-1970 00:00:01 GMT; Path=/; Secure; SameSite=lax, flownative_oidc_jwt=; Expires=Thu, 01-Jan-1970 00:00:01 GMT; Path=/; Secure; SameSite=lax'],
        ];
    }

    /**
     * @test
     * @dataProvider removeJwtCookieDataProvider
     */
    public function removeJwtCookieTests(array $options, array $authenticationProviderConfiguration, array $authenticatedTokens, array $activeCookies, ?string $expectedCookieHeader = null): void
    {
        $middleware = $this->getMiddleware($options, $authenticationProviderConfiguration);
        $this->mockSecurityContext->method('isInitialized')->willReturn(true);
        $mockTokens = [];
        foreach ($authenticatedTokens as $tokenProviderName) {
            $mockOpenIdConnectToken = new OpenIdConnectToken();
            $mockOpenIdConnectToken->setAuthenticationProviderName($tokenProviderName);
            $mockTokens[] = $mockOpenIdConnectToken;
        }
        $this->mockSecurityContext->method('getAuthenticationTokensOfType')->willReturn($mockTokens);
        $this->mockRequest->method('getCookieParams')->willReturn(array_flip($activeCookies));

        $this->mockNextRequestHandler->originalResponse = new Response();
        $response = $middleware->process($this->mockRequest, $this->mockNextRequestHandler);
        if ($expectedCookieHeader === null) {
            self::assertFalse($response->hasHeader('Set-Cookie'));
        } else {
            self::assertSame($expectedCookieHeader, $response->getHeaderLine('Set-Cookie'));
        }
    }

    public static function setJwtCookieDataProvider(): array
    {
        $jwt = self::JWT_NODY;
        return [
            'no authenticated tokens' => ['options' => [], 'authenticationProviderConfiguration' => [], 'authenticatedTokens' => [], 'activeCookies' => ['flownative_oidc_jwt'], 'expectedCookieHeader' => null],
            'authenticated, no active cookie' => ['options' => [], 'authenticationProviderConfiguration' => [], 'authenticatedTokens' => ['SomeProvider'], 'activeCookies' => [], 'expectedCookieHeader' => 'flownative_oidc_jwt=' . self::JWT_NODY . '; Path=/; Secure; SameSite=lax'],
            'authenticated, different active cookie name' => ['options' => [], 'authenticationProviderConfiguration' => [], 'authenticatedTokens' => ['SomeProvider'], 'activeCookies' => ['SomeOtherCookie'], 'expectedCookieHeader' => 'flownative_oidc_jwt=' . self::JWT_NODY . '; Path=/; Secure; SameSite=lax'],

            'authenticated, default options' => ['options' => [], 'authenticationProviderConfiguration' => [], 'authenticatedTokens' => ['SomeProvider'], 'activeCookies' => ['flownative_oidc_jwt'], 'expectedCookieHeader' => 'flownative_oidc_jwt=' . self::JWT_NODY . '; Path=/; Secure; SameSite=lax'],
            'two authenticated tokens, default options' => ['options' => [], 'authenticationProviderConfiguration' => [], 'authenticatedTokens' => ['SomeProvider', 'SomeOtherProvider'], 'activeCookies' => ['flownative_oidc_jwt'], 'expectedCookieHeader' => 'flownative_oidc_jwt=' . self::JWT_NODY . '; Path=/; Secure; SameSite=lax, flownative_oidc_jwt=' . self::JWT_JODY . '; Path=/; Secure; SameSite=lax'],
            'option cookie.name' => ['options' => ['cookie' => ['name' => 'SomeCookieName']], 'authenticationProviderConfiguration' => [], 'authenticatedTokens' => ['SomeProvider'], 'activeCookies' => ['SomeCookieName'], 'expectedCookieHeader' => 'SomeCookieName=' . self::JWT_NODY . '; Path=/; Secure; SameSite=lax'],
            'option cookie.secure' => ['options' => ['cookie' => ['secure' => false]], 'authenticationProviderConfiguration' => [], 'authenticatedTokens' => ['SomeProvider'], 'activeCookies' => ['flownative_oidc_jwt'], 'expectedCookieHeader' => 'flownative_oidc_jwt=' . self::JWT_NODY . '; Path=/; SameSite=lax'],
            'option cookie.httpOnly' => ['options' => ['cookie' => ['httpOnly' => true]], 'authenticationProviderConfiguration' => [], 'authenticatedTokens' => ['SomeProvider'], 'activeCookies' => ['flownative_oidc_jwt'], 'expectedCookieHeader' => 'flownative_oidc_jwt=' . self::JWT_NODY . '; Path=/; Secure; HttpOnly; SameSite=lax'],
            'option cookie.sameSite' => ['options' => ['cookie' => ['sameSite' => 'lax']], 'authenticationProviderConfiguration' => [], 'authenticatedTokens' => ['SomeProvider'], 'activeCookies' => ['flownative_oidc_jwt'], 'expectedCookieHeader' => 'flownative_oidc_jwt=' . self::JWT_NODY . '; Path=/; Secure; SameSite=lax'],

            'option.secureCookie (compat)' => ['options' => ['secureCookie' => false], 'authenticationProviderConfiguration' => [], 'authenticatedTokens' => ['SomeProvider'], 'activeCookies' => ['flownative_oidc_jwt'], 'expectedCookieHeader' => 'flownative_oidc_jwt=' . self::JWT_NODY . '; Path=/; SameSite=lax'],
            'option.secureCookie (compat) overrides cookie.secure' => ['options' => ['secureCookie' => false, 'cookie' => ['secure' => true]], 'authenticationProviderConfiguration' => [], 'authenticatedTokens' => ['SomeProvider'], 'activeCookies' => ['flownative_oidc_jwt'], 'expectedCookieHeader' => 'flownative_oidc_jwt=' . self::JWT_NODY . '; Path=/; SameSite=lax'],

            'option.cookieName (compat)' => ['options' => ['cookieName' => 'SomeCookieName'], 'authenticationProviderConfiguration' => [], 'authenticatedTokens' => ['SomeProvider'], 'activeCookies' => ['SomeCookieName'], 'expectedCookieHeader' => 'SomeCookieName=' . self::JWT_NODY . '; Path=/; Secure; SameSite=lax'],
            'option.cookieName (compat) overrides cookie.name' => ['options' => ['cookieName' => 'SomeCookieName', 'cookie' => ['name' => 'SomeOtherCookieName']], 'authenticationProviderConfiguration' => [], 'authenticatedTokens' => ['SomeProvider'], 'activeCookies' => ['SomeCookieName'], 'expectedCookieHeader' => 'SomeCookieName=' . self::JWT_NODY . '; Path=/; Secure; SameSite=lax'],
            'providerOption.jwtCookieName overrides cookie name options' => ['options' => ['cookieName' => 'SomeCookieName', 'cookie' => ['name' => 'SomeOtherCookieName']], 'authenticationProviderConfiguration' => ['SomeProvider' => ['providerOptions' => ['jwtCookieName' => 'ProviderCookieName']]], 'authenticatedTokens' => ['SomeProvider'], 'activeCookies' => ['SomeCookieName', 'SomeOtherCookieName', 'ProviderCookieName'], 'expectedCookieHeader' => 'ProviderCookieName=' . self::JWT_NODY . '; Path=/; Secure; SameSite=lax'],

            'two authenticated tokens with different cookie names' => [[], 'authenticationProviderConfiguration' => ['SomeProvider' => ['providerOptions' => ['jwtCookieName' => 'ProviderCookieName']]], 'authenticatedTokens' => ['SomeProvider', 'SomeOtherProvider'], 'activeCookies' => ['flownative_oidc_jwt', 'ProviderCookieName'], 'expectedCookieHeader' => 'ProviderCookieName=' . self::JWT_NODY . '; Path=/; Secure; SameSite=lax, flownative_oidc_jwt=' . self::JWT_JODY . '; Path=/; Secure; SameSite=lax'],
        ];
    }

    /**
     * @test
     * @dataProvider setJwtCookieDataProvider
     */
    public function setJwtCookieTests(array $options, array $authenticationProviderConfiguration, array $authenticatedTokens, array $activeCookies, ?string $expectedCookieHeader = null): void
    {
        $middleware = $this->getMiddleware($options, $authenticationProviderConfiguration);
        $this->mockSecurityContext->method('isInitialized')->willReturn(true);
        $this->mockSecurityContext->method('getAccountByAuthenticationProviderName')->willReturnCallback(function(string $providerName) {
            switch ($providerName) {
                case 'SomeProvider':
                    $mockAccount = $this->getMockBuilder(Account::class)->disableOriginalConstructor()->getMock();
                    $mockAccount->method('getCredentialsSource')->willReturn(self::JWT_NODY);
                    break;
                case 'SomeOtherProvider':
                    $mockAccount = $this->getMockBuilder(Account::class)->disableOriginalConstructor()->getMock();
                    $mockAccount->method('getCredentialsSource')->willReturn(self::JWT_JODY);
                    break;
            }
            return $mockAccount;
        });
        $mockTokens = [];
        foreach ($authenticatedTokens as $tokenProviderName) {
            $mockOpenIdConnectToken = new OpenIdConnectToken();
            $mockOpenIdConnectToken->setAuthenticationProviderName($tokenProviderName);
            $mockTokens[] = $mockOpenIdConnectToken;
        }
        $this->mockSecurityContext->method('getAuthenticationTokensOfType')->willReturn($mockTokens);
        $this->mockRequest->method('getCookieParams')->willReturn(array_flip($activeCookies));

        $this->mockNextRequestHandler->originalResponse = new Response();
        $response = $middleware->process($this->mockRequest, $this->mockNextRequestHandler);
        if ($expectedCookieHeader === null) {
            self::assertFalse($response->hasHeader('Set-Cookie'));
        } else {
            self::assertSame($expectedCookieHeader, $response->getHeaderLine('Set-Cookie'));
        }
    }

    /**
     * @test
     */
    public function processDoesNotSetCookieHeaderIfAuthenticatedAccountDoesNotContainIdentityToken(): void
    {
        $middleware = $this->getMiddleware();
        $this->mockSecurityContext->method('isInitialized')->willReturn(true);
        $mockAccount = $this->getMockBuilder(Account::class)->disableOriginalConstructor()->getMock();
        $mockAccount->method('getCredentialsSource')->willReturn('not-a-jwt-string');
        $this->mockSecurityContext->method('getAccountByAuthenticationProviderName')->willReturn($mockAccount);
        $this->mockSecurityContext->method('getAuthenticationTokensOfType')->willReturn([new OpenIdConnectToken()]);

        $this->mockNextRequestHandler->originalResponse = new Response();
        $response = $middleware->process($this->mockRequest, $this->mockNextRequestHandler);
        self::assertFalse($response->hasHeader('Set-Cookie'));
    }

    public static function removeOidcQueryParametersDataProvider(): array
    {
        return [
            ['requestUri' => 'http://localhost', 'expectedLocationHeader' => null],
            ['requestUri' => 'http://localhost?flownative_oidc=foo', 'expectedLocationHeader' => 'http://localhost'],
            ['requestUri' => 'https://some-domain.tld/?flownative_oidc=foo', 'expectedLocationHeader' => 'https://some-domain.tld/'],
            ['requestUri' => 'http://localhost?flownative_oauth2_authorization_id_oidc=foo', 'expectedLocationHeader' => 'http://localhost'],
            ['requestUri' => 'http://localhost?flownative_oidc=foo&flownative_oauth2_authorization_id_oidc=bar', 'expectedLocationHeader' => 'http://localhost'],
            ['requestUri' => 'https://www.foo-bar.com?flownative_oidc=foo&flownative_oauth2_authorization_id_oidc=bar&bar=baz', 'expectedLocationHeader' => 'https://www.foo-bar.com?bar=baz'],
            ['requestUri' => 'http://localhost?bar=baz&flownative_oidc=foo&flownative_oauth2_authorization_id_oidc=bar&bar=baz', 'expectedLocationHeader' => 'http://localhost?bar=baz&bar=baz'],
            ['requestUri' => 'http://localhost?existing[query]=parameters&flownative_oidc=foo', 'expectedLocationHeader' => 'http://localhost?existing%5Bquery%5D=parameters'],
        ];
    }

    /**
     * @test
     * @dataProvider removeOidcQueryParametersDataProvider
     */
    public function removeOidcQueryParametersTests(string $requestUri, ?string $expectedLocationHeader = null): void
    {
        $middleware = $this->getMiddleware();
        $this->mockSecurityContext->method('isInitialized')->willReturn(true);
        $this->mockSecurityContext->method('getAuthenticationTokensOfType')->willReturn([]);
        $mockRequest = $this->getMockBuilder(ServerRequestInterface::class)->getMock();
        $mockRequest->method('getUri')->willReturn(new Uri($requestUri));
        $this->mockNextRequestHandler->originalResponse = new Response();
        $response = $middleware->process($mockRequest, $this->mockNextRequestHandler);
        if ($expectedLocationHeader === null) {
            self::assertFalse($response->hasHeader('Location'));
        } else {
            self::assertSame($expectedLocationHeader, $response->getHeaderLine('Location'));
        }
    }

    /**
     * @test
     */
    public function removeOidcQueryParametersDoesNotAlterLocationHeaderIfOneIsPresentAlready(): void
    {
        $middleware = $this->getMiddleware();
        $this->mockSecurityContext->method('isInitialized')->willReturn(true);
        $this->mockSecurityContext->method('getAuthenticationTokensOfType')->willReturn([]);
        $mockRequest = $this->getMockBuilder(ServerRequestInterface::class)->getMock();
        $mockRequest->method('getUri')->willReturn(new Uri('http://localhost?flownative_oidc=foo&flownative_oauth2_authorization_id_oidc=bar'));
        $responseWithLocationHeader = new Response(200, ['Location' => 'http://original-redirect.tld']);
        $this->mockNextRequestHandler->originalResponse = $responseWithLocationHeader;
        $response = $middleware->process($mockRequest, $this->mockNextRequestHandler);
        self::assertSame('http://original-redirect.tld', $response->getHeaderLine('Location'));
    }
}
