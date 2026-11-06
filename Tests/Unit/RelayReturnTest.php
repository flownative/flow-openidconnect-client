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

use Doctrine\ORM\EntityManagerInterface;
use Doctrine\Persistence\ObjectRepository;
use Flownative\OAuth2\Client\Authorization;
use Flownative\OAuth2\Client\InvalidSignedStateException;
use Flownative\OAuth2\Client\OAuthClientException;
use Flownative\OAuth2\Client\StateSigner;
use Flownative\OAuth2\Client\StateVerificationKey;
use Flownative\OAuth2\Client\StateVerifier;
use Flownative\OAuth2\Client\UnknownStateException;
use Flownative\OpenIdConnect\Client\Authentication\Nonce;
use Flownative\OpenIdConnect\Client\Authentication\OpenIdConnectEntryPoint;
use Flownative\OpenIdConnect\Client\Authentication\OpenIdConnectToken;
use Flownative\OpenIdConnect\Client\Tests\Unit\Fixtures\JwtFixture;
use Flownative\OpenIdConnect\Client\Tests\Unit\Fixtures\OAuthClientOfHost;
use Flownative\OpenIdConnect\Client\Tests\Unit\Fixtures\OpenIdConnectClientFixture;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\ServerRequest;
use GuzzleHttp\Psr7\Uri;
use Neos\Cache\Backend\TransientMemoryBackend;
use Neos\Cache\Frontend\VariableFrontend;
use Neos\Flow\Mvc\ActionRequest;
use Neos\Flow\ObjectManagement\ObjectManagerInterface;
use Neos\Flow\Security\Cryptography\HashService;
use Neos\Flow\Security\Exception\AccessDeniedException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\UriInterface;
use Psr\Log\LoggerInterface;
use stdClass;

/**
 * A login which starts on one host, returns from the identity provider through a relay and finishes on the host which started it
 *
 * The relay is played by the test: it verifies the state with the public key and forwards code and state to the signed host.
 */
class RelayReturnTest extends TestCase
{
    private const string HOST = 'acme.cell-1.example.com';
    private const string FINISH_AUTHORIZATION_PATH = '/oauth2/oidc/test/finishauthorization';
    private const string RELAY_URI = 'https://login.example.com/oauth2/oidc/test/finishauthorization';
    private const string AUTHORIZATION_ENDPOINT = 'https://id.example.com/authorize';
    private const string RETURN_TO_URI = 'https://' . self::HOST . '/projects?page=2';
    private const string KEY_ID = 'cell-1';
    private const string JWT_COOKIE_NAME = 'flownative_oidc_jwt';

    private array $storedAuthorizations = []; # authorizations persisted through the entity manager stub, by authorization id

    private array $transactions = []; # requests sent to the token endpoint, recorded by Guzzle's history middleware

    private MockHandler $tokenEndpoint;

    private VariableFrontend $stateCache; # shared by the clients of all requests of a test, like the state cache of an application

    private HashService $hashService;

    /**
     * @var array{secretKey: string, publicKey: string}
     */
    private array $stateSigningKeyPair;

    public function setUp(): void
    {
        $this->stateCache = new VariableFrontend('state', new TransientMemoryBackend());
        $this->stateCache->initializeObject();
        $this->tokenEndpoint = new MockHandler();
        $this->hashService = OpenIdConnectClientFixture::createHashService();
        $this->stateSigningKeyPair = StateSigner::generateKeyPair();
    }

    #[Test]
    public function loginWithoutRelayKeepsTheAuthorizationRequestAndTheTokenRequestUnchanged(): void
    {
        $finishAuthorizationUri = 'https://' . self::HOST . self::FINISH_AUTHORIZATION_PATH;
        $client = $this->createClientOnHost();
        $nonce = Nonce::generate();

        $authorizationUri = $client->startAuthorization(new Uri(self::RETURN_TO_URI), 'profile', $nonce);
        parse_str($authorizationUri->getQuery(), $authorizationParameters);
        $this->finishOnHost(self::getState($authorizationUri), self::createIdentityToken($nonce->value), self::createNonceCookies($nonce));

        self::assertMatchesRegularExpression('/^[a-f0-9]{32}\z/', $authorizationParameters['state']);
        $maskedAuthorizationUri = str_replace([$authorizationParameters['state'], $authorizationParameters['code_challenge']], ['STATE', 'CODE_CHALLENGE'], (string)$authorizationUri);
        self::assertSame(self::AUTHORIZATION_ENDPOINT . '?nonce=' . $nonce->value . '&scope=profile%20openid%20offline_access&state=STATE&response_type=code&approval_prompt=auto&code_challenge=CODE_CHALLENGE&code_challenge_method=S256&redirect_uri=' . urlencode($finishAuthorizationUri) . '&client_id=' . OpenIdConnectClientFixture::CLIENT_ID, $maskedAuthorizationUri);
        parse_str((string)$this->transactions[0]['request']->getBody(), $tokenRequestParameters);
        self::assertSame($finishAuthorizationUri, $tokenRequestParameters['redirect_uri']);
        self::assertNull($client->getRedirectUri());
        self::assertNull($client->getStateSigner());
    }

    #[Test]
    public function loginWhichReturnsThroughTheRelayFinishesOnTheHostWhichStartedIt(): void
    {
        $nonce = Nonce::generate();
        $nonceCookies = self::createNonceCookies($nonce);
        $authorizationUri = $this->createClientOnHost(self::relayOptions())->startAuthorization(new Uri(self::RETURN_TO_URI), 'profile', $nonce);
        parse_str($authorizationUri->getQuery(), $authorizationParameters);

        $forwardUri = $this->forwardThroughRelay($authorizationParameters['state'], 'the-code');
        parse_str($forwardUri->getQuery(), $forwardedParameters);
        $returnUri = $this->finishOnHost($forwardedParameters['state'], self::createIdentityToken($nonce->value), $nonceCookies, $forwardedParameters['code']);
        $identityToken = $this->createTokenOnHost($returnUri, $nonceCookies)->extractIdentityTokenFromRequest(self::JWT_COOKIE_NAME);

        self::assertSame(self::RELAY_URI, $authorizationParameters['redirect_uri']);
        self::assertSame('https://' . self::HOST . self::FINISH_AUTHORIZATION_PATH, (string)$forwardUri->withQuery(''));
        parse_str((string)$this->transactions[0]['request']->getBody(), $tokenRequestParameters);
        self::assertSame(self::RELAY_URI, $tokenRequestParameters['redirect_uri']);
        self::assertSame('the-code', $tokenRequestParameters['code']);
        self::assertSame('https://' . self::HOST . '/projects', (string)$returnUri->withQuery(''));
        $requirements = new IdentityTokenRequirements([OpenIdConnectClientFixture::ISSUER], [OpenIdConnectClientFixture::CLIENT_ID], OpenIdConnectClientFixture::CLIENT_ID, nonce: $nonce->value);
        $validatedIdentityToken = (new IdentityTokenValidator())->validate($identityToken, $this->createClientOnHost(self::relayOptions()), $requirements);
        self::assertSame('alice', $validatedIdentityToken->accountIdentifier);
    }

    #[Test]
    public function loginWhichReturnsThroughTheRelayIsRefusedForTheNonceOfAnotherLogin(): void
    {
        $nonce = Nonce::generate();
        $otherNonce = Nonce::generate();
        // The browser has started both logins, so only the comparison of the nonces tells them apart
        $nonceCookies = array_merge(self::createNonceCookies($nonce), self::createNonceCookies($otherNonce));
        $authorizationUri = $this->createClientOnHost(self::relayOptions())->startAuthorization(new Uri(self::RETURN_TO_URI), 'profile', $nonce);
        parse_str($this->forwardThroughRelay(self::getState($authorizationUri), 'the-code')->getQuery(), $forwardedParameters);
        $returnUri = $this->finishOnHost($forwardedParameters['state'], self::createIdentityToken($otherNonce->value), $nonceCookies);
        $token = $this->createTokenOnHost($returnUri, $nonceCookies);

        try {
            $token->extractIdentityTokenFromRequest(self::JWT_COOKIE_NAME);
            self::fail('The identity token with the nonce of another login was accepted.');
        } catch (AccessDeniedException $exception) {
            self::assertSame(1789131856, $exception->getCode());
        }
    }

    public static function tamperedStates(): array
    {
        $base64UrlEncode = static fn (string $data): string => rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
        return [
            'another target host' => [static fn (array $segments): array => array_replace($segments, [2 => $base64UrlEncode('evil.example.org')])],
            'another host of the same cell' => [static fn (array $segments): array => array_replace($segments, [2 => $base64UrlEncode('other.cell-1.example.com')])],
            'another issue time' => [static fn (array $segments): array => array_replace($segments, [3 => (string)((int)$segments[3] + 1)])],
            'another signature' => [static fn (array $segments): array => array_replace($segments, [5 => $base64UrlEncode(str_repeat("\0", 64))])],
        ];
    }

    /**
     * @param callable(list<string>): list<string> $tamper Changes the segments of the signed state
     */
    #[Test]
    #[DataProvider('tamperedStates')]
    public function tamperedStateIsRefusedByTheRelayAndByTheHost(callable $tamper): void
    {
        $nonce = Nonce::generate();
        $authorizationUri = $this->createClientOnHost(self::relayOptions())->startAuthorization(new Uri(self::RETURN_TO_URI), 'profile', $nonce);
        $tamperedState = implode('.', $tamper(explode('.', self::getState($authorizationUri))));

        try {
            $this->forwardThroughRelay($tamperedState, 'the-code');
            self::fail('The relay forwarded a tampered state.');
        } catch (InvalidSignedStateException) {
        }
        try {
            $this->finishOnHost($tamperedState, self::createIdentityToken($nonce->value), self::createNonceCookies($nonce));
            self::fail('The host finished an authorization with a tampered state.');
        } catch (UnknownStateException $exception) {
            self::assertSame(1558956494, $exception->getCode());
        }
        self::assertSame([], $this->transactions);
    }

    #[Test]
    public function startAuthorizationRefusesToSignHostWhichTheKnownTargetHostsDoNotKnow(): void
    {
        $knownTargetHosts = new class implements KnownTargetHostsInterface {
            public function isKnownTargetHost(string $targetHost): bool
            {
                return $targetHost === 'other.cell-1.example.com';
            }
        };
        $client = $this->createClientOnHost(self::relayOptions(['knownTargetHosts' => 'Acme\KnownTargetHosts']), $knownTargetHosts);

        $this->expectException(OAuthClientException::class);
        $this->expectExceptionCode(1793863404);
        $client->startAuthorization(new Uri(self::RETURN_TO_URI), 'profile', Nonce::generate());
    }

    #[Test]
    public function startAuthorizationSignsHostWhichTheKnownTargetHostsKnow(): void
    {
        $knownTargetHosts = new class implements KnownTargetHostsInterface {
            public function isKnownTargetHost(string $targetHost): bool
            {
                return $targetHost === 'acme.cell-1.example.com';
            }
        };
        $client = $this->createClientOnHost(self::relayOptions(['knownTargetHosts' => 'Acme\KnownTargetHosts']), $knownTargetHosts);

        $authorizationUri = $client->startAuthorization(new Uri(self::RETURN_TO_URI), 'profile', Nonce::generate());

        self::assertSame(self::HOST, $this->createStateVerifier()->verify(self::getState($authorizationUri))->targetHost);
    }

    #[Test]
    public function clientSignsNoStateIfTheRelayOptionsAreEmptyStrings(): void
    {
        $client = $this->createClientOnHost(['redirectUri' => '', 'stateSigning' => ['keyId' => '', 'secretKey' => '', 'allowedHostPatterns' => '', 'knownTargetHosts' => '']]);

        $authorizationUri = $client->startAuthorization(new Uri(self::RETURN_TO_URI), 'profile', Nonce::generate());

        self::assertNull($client->getRedirectUri());
        self::assertNull($client->getStateSigner());
        self::assertMatchesRegularExpression('/^[a-f0-9]{32}\z/', self::getState($authorizationUri));
    }

    #[Test]
    public function clientTreatsARedirectUriOfOnlyAPathAsNotConfigured(): void
    {
        $client = $this->createClientOnHost(['redirectUri' => '/oauth2/oidc/test/finishauthorization']);

        $authorizationUri = $client->startAuthorization(new Uri(self::RETURN_TO_URI), 'profile', Nonce::generate());

        self::assertNull($client->getRedirectUri());
        self::assertMatchesRegularExpression('/^[a-f0-9]{32}\z/', self::getState($authorizationUri));
    }

    #[Test]
    public function clientLogsAnErrorIfTheRedirectUriIsSetButTheSigningKeysAreEmpty(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())->method('error');
        $client = $this->createClientOnHost(self::relayOptions(['keyId' => '', 'secretKey' => '']), logger: $logger);

        self::assertNull($client->getStateSigner());
    }

    #[Test]
    public function clientSignsExactHostPatternsWithoutKnownTargetHosts(): void
    {
        $client = $this->createClientOnHost(self::relayOptions(['allowedHostPatterns' => self::HOST, 'knownTargetHosts' => '']));

        $authorizationUri = $client->startAuthorization(new Uri(self::RETURN_TO_URI), 'profile', Nonce::generate());

        $stateVerifier = new StateVerifier([StateVerificationKey::fromBase64EncodedPublicKey(self::KEY_ID, $this->stateSigningKeyPair['publicKey'], [self::HOST])]);
        self::assertSame(self::HOST, $stateVerifier->verify(self::getState($authorizationUri))->targetHost);
    }

    #[Test]
    public function clientAcceptsAllowedHostPatternsAsCommaSeparatedString(): void
    {
        $knownTargetHosts = new class implements KnownTargetHostsInterface {
            public function isKnownTargetHost(string $targetHost): bool
            {
                return true;
            }
        };
        $client = $this->createClientOnHost(self::relayOptions(['allowedHostPatterns' => ' acme.example.com, ,*.cell-1.example.com ,']), $knownTargetHosts);

        $authorizationUri = $client->startAuthorization(new Uri(self::RETURN_TO_URI), 'profile', Nonce::generate());

        self::assertSame(self::HOST, $this->createStateVerifier()->verify(self::getState($authorizationUri))->targetHost);
    }

    public static function invalidRelayOptions(): array
    {
        return [
            'redirect URI without scheme' => [['redirectUri' => 'relay.example.com/oauth2/oidc/test/finishauthorization'], 1793956456],
            'protocol-relative redirect URI' => [['redirectUri' => '//relay.example.com/oauth2/oidc/test/finishauthorization'], 1793956456],
            'state signing without key id' => [['stateSigning' => ['secretKey' => 'key', 'allowedHostPatterns' => ['*.cell-1.example.com']]], 1793956457],
            'state signing without host patterns' => [['stateSigning' => ['keyId' => self::KEY_ID, 'secretKey' => 'key']], 1793956457],
            'state signing which is no array' => [['stateSigning' => 'cell-1'], 1793956457],
            'secret key which is no Ed25519 key' => [['stateSigning' => ['keyId' => self::KEY_ID, 'secretKey' => base64_encode('short'), 'allowedHostPatterns' => ['acme.cell-1.example.com']]], 1793956459],
            'wildcard without known target hosts' => [['stateSigning' => ['keyId' => self::KEY_ID, 'secretKey' => base64_encode(str_repeat('k', SODIUM_CRYPTO_SIGN_SECRETKEYBYTES)), 'allowedHostPatterns' => ['acme.example.com', '*.cell-1.example.com']]], 1793957288],
            'state signing without secret key' => [['stateSigning' => ['keyId' => self::KEY_ID, 'secretKey' => '', 'allowedHostPatterns' => '*.cell-1.example.com', 'knownTargetHosts' => 'Acme\KnownTargetHosts']], 1793980403],
            'state signing without key id but with secret key' => [['stateSigning' => ['keyId' => '', 'secretKey' => base64_encode(str_repeat('k', SODIUM_CRYPTO_SIGN_SECRETKEYBYTES)), 'allowedHostPatterns' => '*.cell-1.example.com', 'knownTargetHosts' => 'Acme\KnownTargetHosts']], 1793980403],
            'wildcard without known target hosts in an empty string' => [['stateSigning' => ['keyId' => self::KEY_ID, 'secretKey' => base64_encode(str_repeat('k', SODIUM_CRYPTO_SIGN_SECRETKEYBYTES)), 'allowedHostPatterns' => '*.cell-1.example.com', 'knownTargetHosts' => '']], 1793957288],
            'state signing with keys but an empty host pattern string' => [['stateSigning' => ['keyId' => self::KEY_ID, 'secretKey' => base64_encode(str_repeat('k', SODIUM_CRYPTO_SIGN_SECRETKEYBYTES)), 'allowedHostPatterns' => ' , ']], 1793956459],
            'key id of whitespace only' => [['stateSigning' => ['keyId' => '  ', 'secretKey' => base64_encode(str_repeat('k', SODIUM_CRYPTO_SIGN_SECRETKEYBYTES)), 'allowedHostPatterns' => ['acme.cell-1.example.com']]], 1793956459],
            'secret key of whitespace only' => [['stateSigning' => ['keyId' => self::KEY_ID, 'secretKey' => '  ', 'allowedHostPatterns' => ['acme.cell-1.example.com']]], 1793956459],
            'relay over HTTP' => [['redirectUri' => 'http://relay.example.com/oauth2/oidc/test/finishauthorization'], 1793957289],
            'known target hosts which do not implement the interface' => [['stateSigning' => ['keyId' => self::KEY_ID, 'secretKey' => base64_encode(str_repeat('k', SODIUM_CRYPTO_SIGN_SECRETKEYBYTES)), 'allowedHostPatterns' => ['*.cell-1.example.com'], 'knownTargetHosts' => 'Acme\KnownTargetHosts']], 1793956458],
        ];
    }

    #[Test]
    public function clientAcceptsRelayOverHttpIfTheLoginCookiesAreNotSecure(): void
    {
        $client = $this->createClientOnHost(array_merge(self::relayOptions(), ['redirectUri' => 'http://relay.example.com/finish']), middlewareSettings: ['cookie' => ['secure' => false]]);

        self::assertSame('http://relay.example.com/finish', $client->getRedirectUri());
    }

    public static function hostsWhichGetNoSignedState(): array
    {
        return [
            'outside of the patterns' => ['acme.cell-2.example.com'],
            'trailing dot' => ['acme.cell-1.example.com.'],
            'underscore' => ['foo_bar.cell-1.example.com'],
            'leading hyphen' => ['-x.cell-1.example.com'],
        ];
    }

    #[Test]
    #[DataProvider('hostsWhichGetNoSignedState')]
    public function entryPointStartsNoLoginForHostWhichGetsNoSignedState(string $host): void
    {
        $client = $this->createClientOnHost(self::relayOptions(), host: $host);
        $clientFactory = $this->createStub(OpenIdConnectClientFactory::class);
        $clientFactory->method('create')->willReturn($client);
        $entryPoint = new OpenIdConnectEntryPoint();
        $entryPoint->setOptions(['serviceName' => OpenIdConnectClientFixture::SERVICE_NAME]);
        OpenIdConnectClientFixture::inject($entryPoint, 'logger', $this->createStub(LoggerInterface::class));
        OpenIdConnectClientFixture::inject($entryPoint, 'openIdConnectClientFactory', $clientFactory);
        $givenResponse = new Response();

        $response = $entryPoint->startAuthentication(new ServerRequest('GET', 'https://' . $host . '/projects'), $givenResponse);

        self::assertSame($givenResponse, $response);
        self::assertFalse($response->hasHeader('Location'));
        self::assertSame([], $this->storedAuthorizations);
    }

    #[Test]
    #[DataProvider('invalidRelayOptions')]
    public function clientRefusesInvalidRelayOptions(array $serviceOptions, int $expectedExceptionCode): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionCode($expectedExceptionCode);
        $this->createClientOnHost($serviceOptions, new stdClass());
    }

    private function relayOptions(array $stateSigningOptions = []): array
    {
        return [
            'redirectUri' => self::RELAY_URI,
            'stateSigning' => array_merge([
                'keyId' => self::KEY_ID,
                'secretKey' => $this->stateSigningKeyPair['secretKey'],
                'allowedHostPatterns' => ['*.cell-1.example.com'],
                'knownTargetHosts' => 'Acme\KnownTargetHosts',
            ], $stateSigningOptions),
        ];
    }

    /**
     * Returns the OpenID Connect client of a request to the host, as every request creates it anew
     */
    private function createClientOnHost(array $serviceOptions = [], ?object $knownTargetHosts = null, string $host = self::HOST, array $middlewareSettings = [], ?LoggerInterface $logger = null): OpenIdConnectClient
    {
        return $this->createClientsOnHost($serviceOptions, $knownTargetHosts, $host, $middlewareSettings, $logger)[0];
    }

    /**
     * @return array{OpenIdConnectClient, OAuthClientOfHost}
     */
    private function createClientsOnHost(array $serviceOptions = [], ?object $knownTargetHosts = null, string $host = self::HOST, array $middlewareSettings = [], ?LoggerInterface $logger = null): array
    {
        $objectManager = $this->createStub(ObjectManagerInterface::class);
        $objectManager->method('get')->willReturn($knownTargetHosts ?? new class implements KnownTargetHostsInterface {
            public function isKnownTargetHost(string $targetHost): bool
            {
                return true;
            }
        });
        $handlerStack = HandlerStack::create($this->tokenEndpoint);
        $handlerStack->push(Middleware::history($this->transactions));
        $httpClientFactory = $this->createStub(HttpClientFactoryInterface::class);
        $httpClientFactory->method('create')->willReturn(new HttpClient(['handler' => $handlerStack]));

        $oAuthClient = new OAuthClientOfHost(OpenIdConnectClientFixture::SERVICE_NAME, 'https://' . $host . self::FINISH_AUTHORIZATION_PATH);
        $oAuthClient->injectEntityManager($this->createInMemoryEntityManager());
        OpenIdConnectClientFixture::inject($oAuthClient, 'stateCache', $this->stateCache);
        OpenIdConnectClientFixture::inject($oAuthClient, 'httpClientFactory', $httpClientFactory);
        OpenIdConnectClientFixture::inject($oAuthClient, 'logger', $this->createStub(LoggerInterface::class));

        $client = OpenIdConnectClientFixture::createClient($oAuthClient, $this->hashService, $logger ?? $this->createStub(LoggerInterface::class), JwtFixture::createJwks(), null, array_merge(['authorizationEndpoint' => self::AUTHORIZATION_ENDPOINT], $serviceOptions), $objectManager, $middlewareSettings);
        $oAuthClient->setOpenIdConnectClient($client);
        return [$client, $oAuthClient];
    }

    /**
     * Verifies the state like the relay and returns the URI to which it forwards the browser
     *
     * @throws InvalidSignedStateException
     */
    private function forwardThroughRelay(string $state, string $code): UriInterface
    {
        $targetHost = $this->createStateVerifier()->verify($state)->targetHost;
        return (new Uri('https://' . $targetHost . self::FINISH_AUTHORIZATION_PATH))->withQuery(http_build_query(['code' => $code, 'state' => $state]));
    }

    /**
     * Finishes the authorization in a new request to the host, with an identity token from the token endpoint
     */
    private function finishOnHost(string $state, string $identityTokenJwt, array $cookies, string $code = 'the-code'): UriInterface
    {
        $this->tokenEndpoint->append(new Response(200, ['Content-Type' => 'application/json'], json_encode(['access_token' => 'the-access-token', 'token_type' => 'Bearer', 'expires_in' => 3600, 'id_token' => $identityTokenJwt], JSON_THROW_ON_ERROR)));
        [, $oAuthClient] = $this->createClientsOnHost(self::relayOptions());
        return $oAuthClient->finishAuthorization($state, $code, $cookies);
    }

    /**
     * Returns the token of the request in which the browser arrives at the return URI, with the claimed identity token
     */
    private function createTokenOnHost(UriInterface $returnUri, array $cookies): OpenIdConnectToken
    {
        $clientFactory = $this->createStub(OpenIdConnectClientFactory::class);
        $clientFactory->method('create')->willReturn($this->createClientOnHost(self::relayOptions()));
        $token = new OpenIdConnectToken();
        OpenIdConnectClientFixture::inject($token, 'openIdConnectClientFactory', $clientFactory);
        OpenIdConnectClientFixture::inject($token, 'hashService', $this->hashService);

        parse_str($returnUri->getQuery(), $queryParameters);
        $httpRequest = (new ServerRequest('GET', $returnUri))->withCookieParams($cookies)->withQueryParams($queryParameters);
        $token->updateCredentials(ActionRequest::fromHttpRequest($httpRequest));
        return $token;
    }

    private function createStateVerifier(): StateVerifier
    {
        return new StateVerifier([StateVerificationKey::fromBase64EncodedPublicKey(self::KEY_ID, $this->stateSigningKeyPair['publicKey'], ['*.cell-1.example.com'])]);
    }

    private function createInMemoryEntityManager(): EntityManagerInterface
    {
        $repository = $this->createStub(ObjectRepository::class);
        $repository->method('find')->willReturnCallback(fn (array $criteria): ?Authorization => $this->storedAuthorizations[$criteria['authorizationId']] ?? null);

        $entityManager = $this->createStub(EntityManagerInterface::class);
        $entityManager->method('getRepository')->willReturn($repository);
        $entityManager->method('find')->willReturnCallback(fn (string $className, mixed $id): ?Authorization => $this->storedAuthorizations[is_array($id) ? $id['authorizationId'] : $id] ?? null);
        $entityManager->method('persist')->willReturnCallback(function (Authorization $authorization): void {
            $this->storedAuthorizations[$authorization->getAuthorizationId()] = $authorization;
        });
        $entityManager->method('remove')->willReturnCallback(function (Authorization $authorization): void {
            unset($this->storedAuthorizations[$authorization->getAuthorizationId()]);
        });
        return $entityManager;
    }

    private static function createIdentityToken(string $nonce): string
    {
        return JwtFixture::createSignedJwt(['iss' => OpenIdConnectClientFixture::ISSUER, 'aud' => OpenIdConnectClientFixture::CLIENT_ID, 'sub' => 'alice', 'nonce' => $nonce, 'iat' => time(), 'exp' => time() + 300]);
    }

    private static function createNonceCookies(Nonce $nonce): array
    {
        $cookie = $nonce->createCookie(CookieSettings::fromMiddlewareSettings([]));
        return [$cookie->getName() => $cookie->getValue()];
    }

    private static function getState(UriInterface $authorizationUri): string
    {
        parse_str($authorizationUri->getQuery(), $queryParameters);
        return $queryParameters['state'];
    }
}
