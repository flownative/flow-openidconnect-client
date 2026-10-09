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

use Flownative\OpenIdConnect\Client\Authentication\IdentityTokenOfLogin;
use Flownative\OpenIdConnect\Client\Authentication\OpenIdConnectSessionToken;
use Flownative\OpenIdConnect\Client\Authentication\OpenIdConnectToken;
use Flownative\OpenIdConnect\Client\Tests\Unit\Fixtures\JwtFixture;
use Flownative\OpenIdConnect\Client\Tests\Unit\Fixtures\OpenIdConnectClientFixture;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Psr7\Query;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\Uri;
use Neos\Flow\Security\Account;
use Neos\Flow\Security\Authentication\TokenInterface;
use Neos\Flow\Security\Context as SecurityContext;
use Neos\Flow\Session\SessionInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;

/**
 * Signing out at the identity provider: the end session URI of the client and the identity token of the login for its hint
 */
class EndSessionTest extends TestCase
{
    private const string END_SESSION_ENDPOINT = 'https://id.example.com/oidc/logout';

    #[Test]
    public function buildEndSessionUriReturnsNullIfTheIdentityProviderOffersNoEndpoint(): void
    {
        static::assertNull($this->createClient()->buildEndSessionUri());
    }

    #[Test]
    public function buildEndSessionUriUsesConfiguredEndpointAndAddsTheParameters(): void
    {
        $identityToken = IdentityToken::fromJwt(JwtFixture::createSignedJwt(['sub' => 'alice']));

        $endSessionUri = $this->createClient(['endSessionEndpoint' => self::END_SESSION_ENDPOINT . '?ui=compact'])->buildEndSessionUri($identityToken, new Uri('https://app.example.com/signed-out'), 'the-state');

        static::assertSame(self::END_SESSION_ENDPOINT, (string)$endSessionUri->withQuery(''));
        static::assertSame([
            'ui' => 'compact',
            'client_id' => OpenIdConnectClientFixture::CLIENT_ID,
            'id_token_hint' => $identityToken->asJwt(),
            'post_logout_redirect_uri' => 'https://app.example.com/signed-out',
            'state' => 'the-state',
        ], Query::parse($endSessionUri->getQuery()));
    }

    #[Test]
    public function buildEndSessionUriOnlyAddsTheClientIdWithoutFurtherArguments(): void
    {
        $endSessionUri = $this->createClient(['endSessionEndpoint' => self::END_SESSION_ENDPOINT])->buildEndSessionUri();

        static::assertSame(['client_id' => OpenIdConnectClientFixture::CLIENT_ID], Query::parse($endSessionUri->getQuery()));
    }

    #[Test]
    public function buildEndSessionUriPrefersTheEndpointOfTheDiscoveryDocument(): void
    {
        $httpClient = $this->createStub(HttpClient::class);
        $httpClient->method('request')->willReturn(new Response(200, [], json_encode([
            'issuer' => OpenIdConnectClientFixture::ISSUER,
            'jwks_uri' => OpenIdConnectClientFixture::JWKS_URI,
            'end_session_endpoint' => 'https://id.example.com/discovered/logout',
        ], JSON_THROW_ON_ERROR)));

        $client = $this->createClient(['discoveryUri' => 'https://id.example.com/.well-known/openid-configuration', 'endSessionEndpoint' => self::END_SESSION_ENDPOINT], $httpClient);

        static::assertSame('https://id.example.com/discovered/logout', (string)$client->buildEndSessionUri()->withQuery(''));
    }

    public static function unusableDiscoveredEndSessionEndpoints(): array
    {
        return [
            'empty' => [''],
            'null' => [null],
            'not a string' => [['https://id.example.com/logout']],
            'relative' => ['/oidc/logout'],
        ];
    }

    #[Test]
    #[DataProvider('unusableDiscoveredEndSessionEndpoints')]
    public function buildEndSessionUriKeepsConfiguredEndpointIfTheDiscoveryDocumentPublishesAnUnusableOne(mixed $discoveredEndSessionEndpoint): void
    {
        $httpClient = $this->createStub(HttpClient::class);
        $httpClient->method('request')->willReturn(new Response(200, [], json_encode([
            'issuer' => OpenIdConnectClientFixture::ISSUER,
            'jwks_uri' => OpenIdConnectClientFixture::JWKS_URI,
            'end_session_endpoint' => $discoveredEndSessionEndpoint,
        ], JSON_THROW_ON_ERROR)));

        $client = $this->createClient(['discoveryUri' => 'https://id.example.com/.well-known/openid-configuration', 'endSessionEndpoint' => self::END_SESSION_ENDPOINT], $httpClient);

        static::assertSame(self::END_SESSION_ENDPOINT, (string)$client->buildEndSessionUri()->withQuery(''));
    }

    #[Test]
    public function initializeObjectRejectsEndSessionEndpointWhichIsNotAnAbsoluteUri(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionCode(1791540876);
        $this->createClient(['endSessionEndpoint' => '/oidc/logout']);
    }

    #[Test]
    public function findReturnsTheIdentityTokenWhichTheAccountOfAJwtLoginCarries(): void
    {
        $jwt = JwtFixture::createSignedJwt(['sub' => 'alice']);
        $account = new Account();
        $account->setCredentialsSource($jwt);
        $token = new OpenIdConnectToken();
        $token->setAuthenticationProviderName('Acme:OpenIdConnect');
        $token->setAccount($account);
        $token->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);

        static::assertSame($jwt, $this->createIdentityTokenOfLogin([$token])->find('Acme:OpenIdConnect')?->asJwt());
    }

    #[Test]
    public function findReturnsTheIdentityTokenWhichASessionLoginRemembered(): void
    {
        $identityToken = IdentityToken::fromJwt(JwtFixture::createSignedJwt(['sub' => 'alice']));
        $token = self::createAuthenticatedSessionToken('Acme:OpenIdConnect');
        $identityTokenOfLogin = $this->createIdentityTokenOfLogin([$token]);

        $identityTokenOfLogin->rememberInSession('Acme:OpenIdConnect', $identityToken);

        static::assertSame($identityToken->asJwt(), $identityTokenOfLogin->find('Acme:OpenIdConnect')?->asJwt());
    }

    #[Test]
    public function findReturnsNullForAnotherProviderOrWithoutLogin(): void
    {
        $identityToken = IdentityToken::fromJwt(JwtFixture::createSignedJwt(['sub' => 'alice']));
        $notAuthenticatedToken = new OpenIdConnectSessionToken();
        $notAuthenticatedToken->setAuthenticationProviderName('Acme:Other');
        $identityTokenOfLogin = $this->createIdentityTokenOfLogin([self::createAuthenticatedSessionToken('Acme:OpenIdConnect'), $notAuthenticatedToken]);
        $identityTokenOfLogin->rememberInSession('Acme:Other', $identityToken);

        static::assertNull($identityTokenOfLogin->find('Acme:Other'));
        static::assertNull($identityTokenOfLogin->find('Acme:Unknown'));
    }

    #[Test]
    public function findReturnsNullIfTheSessionHoldsNoIdentityToken(): void
    {
        static::assertNull($this->createIdentityTokenOfLogin([self::createAuthenticatedSessionToken('Acme:OpenIdConnect')])->find('Acme:OpenIdConnect'));
    }

    private function createClient(array $serviceOptions = [], ?HttpClient $httpClient = null): OpenIdConnectClient
    {
        return OpenIdConnectClientFixture::createClient($this->createStub(OAuthClient::class), OpenIdConnectClientFixture::createHashService(), $this->createStub(LoggerInterface::class), JwtFixture::createJwks(), $httpClient, $serviceOptions);
    }

    /**
     * @param TokenInterface[] $tokens
     */
    private function createIdentityTokenOfLogin(array $tokens): IdentityTokenOfLogin
    {
        $securityContext = $this->createStub(SecurityContext::class);
        $securityContext->method('getAuthenticationTokensOfType')->willReturn($tokens);
        $sessionData = [];
        $started = false;
        $session = $this->createStub(SessionInterface::class);
        $session->method('isStarted')->willReturnCallback(static function () use (&$started): bool {
            return $started;
        });
        $session->method('start')->willReturnCallback(static function () use (&$started): void {
            $started = true;
        });
        $session->method('putData')->willReturnCallback(static function (string $key, mixed $data) use (&$sessionData): void {
            $sessionData[$key] = $data;
        });
        $session->method('getData')->willReturnCallback(static function (string $key) use (&$sessionData): mixed {
            return $sessionData[$key] ?? null;
        });

        $identityTokenOfLogin = new IdentityTokenOfLogin();
        OpenIdConnectClientFixture::inject($identityTokenOfLogin, 'securityContext', $securityContext);
        OpenIdConnectClientFixture::inject($identityTokenOfLogin, 'session', $session);
        return $identityTokenOfLogin;
    }

    private static function createAuthenticatedSessionToken(string $authenticationProviderName): OpenIdConnectSessionToken
    {
        $token = new OpenIdConnectSessionToken();
        $token->setAuthenticationProviderName($authenticationProviderName);
        $token->setAccount(new Account());
        $token->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);
        return $token;
    }
}
