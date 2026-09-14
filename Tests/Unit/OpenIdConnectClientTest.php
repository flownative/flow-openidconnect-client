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

use DateTimeImmutable;
use Flownative\OAuth2\Client\Authorization;
use Flownative\OAuth2\Client\BrowserBinding;
use Flownative\OpenIdConnect\Client\Authentication\Nonce;
use Flownative\OpenIdConnect\Client\Authentication\OpenIdConnectToken;
use Flownative\OpenIdConnect\Client\Tests\Unit\Fixtures\JwtFixture;
use RuntimeException;
use Flownative\OpenIdConnect\Client\Tests\Unit\Fixtures\OpenIdConnectClientFixture;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\Uri;
use League\OAuth2\Client\Token\AccessToken;
use Neos\Cache\Backend\TransientMemoryBackend;
use Neos\Cache\Frontend\VariableFrontend;
use Neos\Flow\Utility\Algorithms;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Message\UriInterface;
use Psr\Log\LoggerInterface;
use ReflectionException;

class OpenIdConnectClientTest extends TestCase
{
    /**
     * @var OpenIdConnectClient
     */
    protected $oidcClient;

    /**
     * @var OAuthClient | MockObject
     */
    protected $oAuthClient;

    /**
     * @var VariableFrontend
     */
    protected $discoveryCache;

    /**
     * @var VariableFrontend
     */
    protected $jwksCache;

    /**
     * @var array
     */
    protected $settings = [
        'services' => [
            'test' => [
                'options' => [
                    'jwksUri' => 'http://localhost'
                ]
            ]
        ]
    ];

    /**
     * @var string
     */
    protected $exampleJwksJson = '[{"alg":"RS256","kty":"RSA","use":"sig","n":"0sq7-7N5qS1S2YHzWmeHI5TJwm7RdXZO4NmeRR-bKa1E7nSgvNp0EE5GlIHLWjwWoH3qgAurhvCeGbxMCj_oCmxCRBGpJR8TUU0YUD83XBCgDH626LdId7EQbw5n-cAGoIViqyJ1Mes6WX7ECeD9IvEwf0YQ5lTbA8gvP-5KDypPV3KW_e-xq05uyOPFZCi4QlSJjGQkB_Sbfrtca3yRmMYYZlYNQpb5eoLTDkSUhp3Eo3bqYu3MOXgrasvM010trnMX_QqKffAaqzD_It7ATr4IWtQjIbFLeF_0tg2QzcTk9hcbl1z4fnP_7pJOK4IlK2wTg2tNynGS9y2xwtEAYw","e":"AQAB","kid":"RTFBOTM4NkVBMTE3MzE3NzczQzA5OUZEQTg5QUVCRjZCMjRGQzg0Rg","x5t":"RTFBOTM4NkVBMTE3MzE3NzczQzA5OUZEQTg5QUVCRjZCMjRGQzg0Rg","x5c":["MIIDETCCAfmgAwIBAgIJfTUExzsuzGKIMA0GCSqGSIb3DQEBCwUAMCYxJDAiBgNVBAMTG2Zsb3duYXRpdmUtZGV2LmV1LmF1dGgwLmNvbTAeFw0xOTA4MjYwODU1MDBaFw0zMzA1MDQwODU1MDBaMCYxJDAiBgNVBAMTG2Zsb3duYXRpdmUtZGV2LmV1LmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANLKu\/uzeaktUtmB81pnhyOUycJu0XV2TuDZnkUfmymtRO50oLzadBBORpSBy1o8FqB96oALq4bwnhm8TAo\/6ApsQkQRqSUfE1FNGFA\/N1wQoAx+tui3SHexEG8OZ\/nABqCFYqsidTHrOll+xAng\/SLxMH9GEOZU2wPILz\/uSg8qT1dylv3vsatObsjjxWQouEJUiYxkJAf0m367XGt8kZjGGGZWDUKW+XqC0w5ElIadxKN26mLtzDl4K2rLzNNdLa5zF\/0Kin3wGqsw\/yLewE6+CFrUIyGxS3hf9LYNkM3E5PYXG5dc+H5z\/+6STiuCJStsE4NrTcpxkvctscLRAGMCAwEAAaNCMEAwDwYDVR0TAQH\/BAUwAwEB\/zAdBgNVHQ4EFgQUGF4U4Ej+lmo\/L6nebp1Z6Ps\/CVowDgYDVR0PAQH\/BAQDAgKEMA0GCSqGSIb3DQEBCwUAA4IBAQDP2Z3UaZoAXSCDt7egQ9WwDk8kP7rAcJbvFHjoHE5k7qEbWXK0BpjYBlSWdTt7zR6toaU3pGrKFaQFDtSgkdOrmmm3z7kr6Q++R2jQWD+R0nPf5OM3\/CFC7xks2kvf3EE6MQO+XE4D0pWtnZRNWFosYY9c+qQf5nRbXVbjpPr7nFFFRboylbYrco87YqmTF580dbNMVagMLlmjIYt0Un0ROVF5hbZt0A1egZrMbzC3hYWta2GboGI8\/W9Do2btH1oFciBkBLRhW4ZyJl62Jz0HysFQ8Wqj6OW5uDdx139GKpUQ2h1qUMz4bRJg5ESC51woPDrdEe\/DwCV+nNU35\/am"]},{"alg":"RS256","kty":"RSA","use":"sig","n":"vV88BrFd5vSXZomkFy1hg-v14ryZ92_6CPPt9hp6yTg6YoDXy_VFznyuZo-hXPj2gczJ0iE2MAF4rlRkj9rYrrghtXYBQadLgbSKrAZYtjNpTOjCmCEKngEwY1FEr4XTQ-5r-TgMRZSOvXZjQSeMN8utHcp97z7oi8orIAGj-NDYc6Zrr9p2tuMy-z95P3WSebbJKk8Zp2YZJYYOBI10RrcHXo5QCRqpwSJLARUbLH56NxDexnvxu9XHJLeIjm9iV4m0fW8sAmrOkKfLD6PouLwQMOWa6fRrTCMUODn_kZTCeWRW8SyAgeCKDGezRBp1AzrbV4-A2ge69qPPa5ckMw","e":"AQAB","kid":"06-mL-BogrPN-w_nc38fY","x5t":"p9T93AF5NvSnHT3iBufNmiJnlkM","x5c":["MIIDETCCAfmgAwIBAgIJMHBYF7g2pxfYMA0GCSqGSIb3DQEBCwUAMCYxJDAiBgNVBAMTG2Zsb3duYXRpdmUtZGV2LmV1LmF1dGgwLmNvbTAeFw0yMDAzMTAxNDUxMjZaFw0zMzExMTcxNDUxMjZaMCYxJDAiBgNVBAMTG2Zsb3duYXRpdmUtZGV2LmV1LmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL1fPAaxXeb0l2aJpBctYYPr9eK8mfdv+gjz7fYaesk4OmKA18v1Rc58rmaPoVz49oHMydIhNjABeK5UZI\/a2K64IbV2AUGnS4G0iqwGWLYzaUzowpghCp4BMGNRRK+F00Pua\/k4DEWUjr12Y0EnjDfLrR3Kfe8+6IvKKyABo\/jQ2HOma6\/adrbjMvs\/eT91knm2ySpPGadmGSWGDgSNdEa3B16OUAkaqcEiSwEVGyx+ejcQ3sZ78bvVxyS3iI5vYleJtH1vLAJqzpCnyw+j6Li8EDDlmun0a0wjFDg5\/5GUwnlkVvEsgIHgigxns0QadQM621ePgNoHuvajz2uXJDMCAwEAAaNCMEAwDwYDVR0TAQH\/BAUwAwEB\/zAdBgNVHQ4EFgQUZfhmgJY5wzMOx9zYBuzpGO9Dct0wDgYDVR0PAQH\/BAQDAgKEMA0GCSqGSIb3DQEBCwUAA4IBAQCDoPZp6VwxX2KAf56UT0aEMTYtWUscVEZA9NGjKzOaYQPVfecW4epDSrD91wtv877kXZKoJZzzrm1iz14UiMCuZ\/O8kuhRx0QTaqSCQ\/hfqK4cy9ahm2rtlkW6zLYuqEb\/ErzFZ\/3cSkzYSph\/OtBa+WAi6wBCYCvTuug0lFfyAalI1vvvY\/oH3b4GUqmjFZkPxK6jdP+tKXuvyr8aKuRoxs6z1bWcaZIddMidg3cCTAp6Xo5wey4CqP3nqYbTBrtnrlGb\/AjETSuzPKhWekdHQMNmflfsauqFkKHPpDg+bTdrk6lw++6xwZLA81qTKA4er0Nld+wgDc0xnMp1gelO"]}]';

    /**
     * @throws
     */
    public function setUp(): void
    {
        $this->discoveryCache = new VariableFrontend('discovery', new TransientMemoryBackend());
        $this->discoveryCache->initializeObject();

        $this->jwksCache = new VariableFrontend('jwks', new TransientMemoryBackend());
        $this->jwksCache->initializeObject();

        $this->oAuthClient = $this->createStub(OAuthClient::class);

        $logger = $this->createStub(LoggerInterface::class);

        $this->oidcClient = new OpenIdConnectClient('test');
        $this->inject($this->oidcClient, 'discoveryCache', $this->discoveryCache);
        $this->inject($this->oidcClient, 'jwksCache', $this->jwksCache);
        $this->inject($this->oidcClient, 'oAuthClient', $this->oAuthClient);
        $this->inject($this->oidcClient, 'logger', $logger);
    }

    #[Test]
    public function startAuthorizationRemovesParametersOfEarlierLoginFromReturnUri(): void
    {
        $returnToUri = null;
        $oAuthClient = $this->createStub(OAuthClient::class);
        $oAuthClient->method('startAuthorization')->willReturnCallback(
            function (string $clientId, UriInterface $givenReturnToUri) use (&$returnToUri): UriInterface {
                $returnToUri = $givenReturnToUri;
                return new Uri('https://id.example.com/authorize');
            }
        );
        $client = OpenIdConnectClientFixture::createClient($oAuthClient, OpenIdConnectClientFixture::createHashService(), $this->createStub(LoggerInterface::class));
        $authorizationIdQueryParameterName = OAuthClient::generateAuthorizationIdQueryParameterName(OAuthClient::SERVICE_TYPE);

        $client->startAuthorization(new Uri('https://www.example.com/secure?page=2&' . OpenIdConnectToken::OIDC_PARAMETER_NAME . '=stale&' . $authorizationIdQueryParameterName . '=stale-id'), 'profile', Nonce::generate());

        parse_str($returnToUri->getQuery(), $queryParameters);
        static::assertSame(['page', OpenIdConnectToken::OIDC_PARAMETER_NAME], array_keys($queryParameters));
        static::assertNotSame('stale', $queryParameters[OpenIdConnectToken::OIDC_PARAMETER_NAME]);
    }

    #[Test]
    public function startAuthorizationBindsTheAuthorizationToTheCookieOfTheNonce(): void
    {
        $browserBinding = null;
        $oAuthClient = $this->createStub(OAuthClient::class);
        $oAuthClient->method('startAuthorization')->willReturnCallback(
            function (string $clientId, UriInterface $returnToUri, string $scope, BrowserBinding $givenBrowserBinding) use (&$browserBinding): UriInterface {
                $browserBinding = $givenBrowserBinding;
                return new Uri('https://id.example.com/authorize');
            }
        );
        $client = OpenIdConnectClientFixture::createClient($oAuthClient, OpenIdConnectClientFixture::createHashService(), $this->createStub(LoggerInterface::class));
        $nonce = Nonce::generate();

        $client->startAuthorization(new Uri('https://www.example.com/secure'), 'profile', $nonce);

        $nonceCookie = $nonce->createCookie(CookieSettings::fromMiddlewareSettings([]));
        static::assertSame($nonceCookie->getName(), $browserBinding->cookieName);
        static::assertTrue(BrowserBinding::isPresentInCookies($browserBinding->cookieName, $browserBinding->getSecretHash(), [$nonceCookie->getName() => $nonceCookie->getValue()]));
    }

    #[Test]
    public function startAuthorizationWarnsIfTheLoginCookiesAreNotSecure(): void
    {
        $oAuthClient = $this->createStub(OAuthClient::class);
        $oAuthClient->method('startAuthorization')->willReturn(new Uri('https://id.example.com/authorize'));
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects($this->once())->method('warning')->with($this->stringContains('not secure'));
        $client = OpenIdConnectClientFixture::createClient($oAuthClient, OpenIdConnectClientFixture::createHashService(), $logger);
        OpenIdConnectClientFixture::inject($client, 'middlewareSettings', ['cookie' => ['secure' => false]]);

        $client->startAuthorization(new Uri('https://www.example.com/secure'), 'profile', Nonce::generate());
    }

    #[Test]
    public function startAuthorizationDoesNotWarnIfTheLoginCookiesAreSecure(): void
    {
        $oAuthClient = $this->createStub(OAuthClient::class);
        $oAuthClient->method('startAuthorization')->willReturn(new Uri('https://id.example.com/authorize'));
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects($this->never())->method('warning');
        $client = OpenIdConnectClientFixture::createClient($oAuthClient, OpenIdConnectClientFixture::createHashService(), $logger);

        $client->startAuthorization(new Uri('https://www.example.com/secure'), 'profile', Nonce::generate());
    }

    #[Test]
    public function getIdentityTokenRemovesTheClaimedAuthorizationEvenIfItContainsNoIdentityToken(): void
    {
        $authorization = new Authorization('oidc-test-authorization', 'oidc', OpenIdConnectClientFixture::CLIENT_ID, Authorization::GRANT_AUTHORIZATION_CODE, 'openid');
        $authorization->setSerializedAccessToken(json_encode(new AccessToken(['access_token' => 'the-access-token']), JSON_THROW_ON_ERROR));
        $oAuthClient = $this->createMock(OAuthClient::class);
        $oAuthClient->expects($this->once())->method('claimAuthorization')->with('the-handle', ['the-cookie' => 'the-secret'])->willReturn($authorization);
        $oAuthClient->expects($this->once())->method('removeAuthorization')->with('oidc-test-authorization');
        $client = OpenIdConnectClientFixture::createClient($oAuthClient, OpenIdConnectClientFixture::createHashService(), $this->createStub(LoggerInterface::class));

        $this->expectException(ServiceException::class);
        $this->expectExceptionCode(1559208674);
        $client->getIdentityToken('the-handle', ['the-cookie' => 'the-secret']);
    }

    #[Test]
    public function getIdentityTokenAcceptsAuthorizationWithoutRefreshToken(): void
    {
        $authorization = new Authorization('oidc-test-authorization', 'oidc', OpenIdConnectClientFixture::CLIENT_ID, Authorization::GRANT_AUTHORIZATION_CODE, 'openid');
        $authorization->setSerializedAccessToken(json_encode(new AccessToken(['access_token' => 'the-access-token', 'id_token' => JwtFixture::createSignedJwt(['sub' => 'the-subject'])]), JSON_THROW_ON_ERROR));
        $oAuthClient = $this->createStub(OAuthClient::class);
        $oAuthClient->method('claimAuthorization')->willReturn($authorization);
        $client = OpenIdConnectClientFixture::createClient($oAuthClient, OpenIdConnectClientFixture::createHashService(), $this->createStub(LoggerInterface::class));

        $tokenSet = $client->getIdentityToken('the-handle', ['the-cookie' => 'the-secret']);

        static::assertSame('', $tokenSet->refreshToken);
    }

    #[Test]
    public function getIdentityTokenReturnsTokenSetIfTheClaimedAuthorizationCannotBeRemoved(): void
    {
        $authorization = new Authorization('oidc-test-authorization', 'oidc', OpenIdConnectClientFixture::CLIENT_ID, Authorization::GRANT_AUTHORIZATION_CODE, 'openid');
        $authorization->setSerializedAccessToken(json_encode(new AccessToken(['access_token' => 'the-access-token', 'id_token' => JwtFixture::createSignedJwt(['sub' => 'the-subject'])]), JSON_THROW_ON_ERROR));
        $oAuthClient = $this->createStub(OAuthClient::class);
        $oAuthClient->method('claimAuthorization')->willReturn($authorization);
        $oAuthClient->method('removeAuthorization')->willThrowException(new RuntimeException('The database is gone'));
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects($this->once())->method('error')->with($this->stringContains('The database is gone'));
        $client = OpenIdConnectClientFixture::createClient($oAuthClient, OpenIdConnectClientFixture::createHashService(), $logger);

        $tokenSet = $client->getIdentityToken('the-handle', ['the-cookie' => 'the-secret']);

        static::assertSame('the-subject', $tokenSet->identityToken->values['sub']);
    }

    #[Test]
    public function getIdentityTokenKeepsTheExceptionOfTheTokenCheckIfTheClaimedAuthorizationCannotBeRemoved(): void
    {
        $authorization = new Authorization('oidc-test-authorization', 'oidc', OpenIdConnectClientFixture::CLIENT_ID, Authorization::GRANT_AUTHORIZATION_CODE, 'openid');
        $authorization->setSerializedAccessToken(json_encode(new AccessToken(['access_token' => 'the-access-token']), JSON_THROW_ON_ERROR));
        $oAuthClient = $this->createStub(OAuthClient::class);
        $oAuthClient->method('claimAuthorization')->willReturn($authorization);
        $oAuthClient->method('removeAuthorization')->willThrowException(new RuntimeException('The database is gone'));
        $client = OpenIdConnectClientFixture::createClient($oAuthClient, OpenIdConnectClientFixture::createHashService(), $this->createStub(LoggerInterface::class));

        $this->expectException(ServiceException::class);
        $this->expectExceptionCode(1559208674);
        $client->getIdentityToken('the-handle', ['the-cookie' => 'the-secret']);
    }

    #[Test]
    public function oAuthClientReturnsTheClientSecretOfTheService(): void
    {
        $oAuthClient = new OAuthClient(OpenIdConnectClientFixture::SERVICE_NAME);
        $oAuthClient->setOpenIdConnectClient(OpenIdConnectClientFixture::createClient($this->createStub(OAuthClient::class), OpenIdConnectClientFixture::createHashService(), $this->createStub(LoggerInterface::class)));

        static::assertSame(OpenIdConnectClientFixture::CLIENT_SECRET, $oAuthClient->getClientSecret(OpenIdConnectClientFixture::CLIENT_ID));
    }

    #[Test]
    public function oAuthClientRejectsClientSecretRequestForAnotherClientId(): void
    {
        $oAuthClient = new OAuthClient(OpenIdConnectClientFixture::SERVICE_NAME);
        $oAuthClient->setOpenIdConnectClient(OpenIdConnectClientFixture::createClient($this->createStub(OAuthClient::class), OpenIdConnectClientFixture::createHashService(), $this->createStub(LoggerInterface::class)));

        $this->expectException(ConfigurationException::class);
        $this->expectExceptionCode(1789395653);
        $oAuthClient->getClientSecret('another-client');
    }

    #[Test]
    public function getJwksReturnsJwksAndStoresItInCache(): void
    {
        $mockHttpClient = $this->createMock(HttpClient::class);
        $mockHttpResponse = $this->createMock(Response::class);
        $mockHttpBody = $this->createMock(StreamInterface::class);

        $this->inject($this->oidcClient, 'settings', $this->settings);
        $this->inject($this->oidcClient, 'httpClient', $mockHttpClient);
        $this->oidcClient->initializeObject();

        $expectedJwks = json_decode($this->exampleJwksJson, true, 512, JSON_THROW_ON_ERROR);
        $cacheEntryIdentifier = sha1($this->settings['services']['test']['options']['jwksUri']);

        $mockHttpClient->expects(static::once())->method('request')->with('GET', $this->settings['services']['test']['options']['jwksUri'])->willReturn($mockHttpResponse);
        $mockHttpResponse->expects(static::once())->method('getBody')->willReturn($mockHttpBody);
        $mockHttpBody->expects(static::once())->method('getContents')->willReturn(json_encode(['keys' => json_decode($this->exampleJwksJson, true, 512, JSON_THROW_ON_ERROR)], JSON_THROW_ON_ERROR, 512));

        $actualJwks = $this->oidcClient->getJwks();

        static::assertSame($expectedJwks, $actualJwks);
        static::assertSame($expectedJwks, $this->jwksCache->get($cacheEntryIdentifier));
    }

    #[Test]
    public function getJwksThrowsExceptionOnFailedDiscoveryRequest(): void
    {
        $mockHttpClient = $this->createMock(HttpClient::class);
        $mockHttpRequest = $this->createStub(Request::class);

        $this->inject($this->oidcClient, 'settings', $this->settings);
        $this->inject($this->oidcClient, 'httpClient', $mockHttpClient);
        $this->oidcClient->initializeObject();

        $mockHttpClient->expects(static::once())->method('request')->willThrowException(new ConnectException('Something wrong', $mockHttpRequest));

        $this->expectExceptionCode(1559211266);
        $this->oidcClient->getJwks();
    }

    #[Test]
    public function getJwksThrowsExceptionOnMalformedResponseFromDiscoveryService(): void
    {
        $mockHttpClient = $this->createMock(HttpClient::class);
        $mockHttpResponse = $this->createMock(Response::class);
        $mockHttpBody = $this->createMock(StreamInterface::class);

        $this->inject($this->oidcClient, 'settings', $this->settings);
        $this->inject($this->oidcClient, 'httpClient', $mockHttpClient);
        $this->oidcClient->initializeObject();

        $mockHttpClient->expects(static::once())->method('request')->with('GET', $this->settings['services']['test']['options']['jwksUri'])->willReturn($mockHttpResponse);
        $mockHttpResponse->expects(static::once())->method('getBody')->willReturn($mockHttpBody);
        $mockHttpBody->expects(static::once())->method('getContents')->willReturn(json_encode(['something invalid' => json_decode($this->exampleJwksJson, true, 512, JSON_THROW_ON_ERROR)], JSON_THROW_ON_ERROR, 512));

        $this->expectExceptionCode(1559211340);
        $this->oidcClient->getJwks();
    }

    #[Test]
    public function getJwksReturnsJwksFromCacheIfItExists(): void
    {
        $this->inject($this->oidcClient, 'settings', $this->settings);
        $this->oidcClient->initializeObject();

        $expectedJwks = json_decode($this->exampleJwksJson, true, 512, JSON_THROW_ON_ERROR);
        $cacheEntryIdentifier = sha1($this->settings['services']['test']['options']['jwksUri']);
        $this->jwksCache->set($cacheEntryIdentifier, $expectedJwks);

        static::assertSame($expectedJwks, $this->oidcClient->getJwks());
    }

    #[Test]
    public function getAccessTokenReturnsAccessTokenFromAuthorization(): void
    {
        $serviceName = 'test';
        $clientId = 'the-client';
        $clientSecret = 'the-secret';
        $scope = 'some';
        $authorizationId = Authorization::generateAuthorizationIdForClientCredentialsGrant($serviceName, $clientId, $scope, []);

        $expectedAccessToken = new AccessToken([
            'access_token' => Algorithms::generateRandomToken(500),
            'expires' => time() + 3600
        ]);

        $authorization = new Authorization($authorizationId, $serviceName, $clientId, Authorization::GRANT_CLIENT_CREDENTIALS, $scope);
        $authorization->setSerializedAccessToken(json_encode($expectedAccessToken, JSON_THROW_ON_ERROR, 512));

        $oAuthClient = $this->createMock(OAuthClient::class);
        $oAuthClient->method('getAuthorization')->willReturnMap([[$authorizationId, $authorization]]);
        $oAuthClient->expects($this->never())->method('requestAccessToken');
        $this->inject($this->oidcClient, 'oAuthClient', $oAuthClient);

        $actualAccessToken = $this->oidcClient->getAccessToken($serviceName, $clientId, $clientSecret, $scope);

        static::assertSame($expectedAccessToken->getToken(), $actualAccessToken->getToken());
        static::assertSame($expectedAccessToken->getExpires(), $actualAccessToken->getExpires());
    }

    #[Test]
    public function getAccessTokenRequestsTokenWithTheGivenScopeOnly(): void
    {
        $authorizationId = Authorization::generateAuthorizationIdForClientCredentialsGrant('test', 'the-client', 'read', ['audience' => 'https://api.example.com']);
        $oAuthClient = $this->createMock(OAuthClient::class);
        $oAuthClient->method('getAuthorization')->willReturnOnConsecutiveCalls(null, self::createAuthorizationWithToken($authorizationId, time() + 3600));
        $oAuthClient->expects($this->once())->method('requestAccessToken')->with('test', 'the-client', 'the-secret', 'read', ['audience' => 'https://api.example.com']);
        $this->inject($this->oidcClient, 'oAuthClient', $oAuthClient);

        $this->oidcClient->getAccessToken('test', 'the-client', 'the-secret', 'read', ['audience' => 'https://api.example.com']);
    }

    #[Test]
    public function getAccessTokenRenewsTokenShortlyBeforeItExpires(): void
    {
        $authorizationId = Authorization::generateAuthorizationIdForClientCredentialsGrant('test', 'the-client', 'read');
        $renewedAuthorization = self::createAuthorizationWithToken($authorizationId, time() + 3600);
        $oAuthClient = $this->createMock(OAuthClient::class);
        $oAuthClient->method('getAuthorization')->willReturnOnConsecutiveCalls(self::createAuthorizationWithToken($authorizationId, time() + 10), $renewedAuthorization);
        $oAuthClient->expects($this->once())->method('requestAccessToken');
        $this->inject($this->oidcClient, 'oAuthClient', $oAuthClient);

        $accessToken = $this->oidcClient->getAccessToken('test', 'the-client', 'the-secret', 'read');

        static::assertSame($renewedAuthorization->getAccessToken()->getToken(), $accessToken->getToken());
    }

    #[Test]
    public function getAccessTokenUsesTokenWithoutExpirationTimeUntilItsAuthorizationExpires(): void
    {
        $authorization = self::createAuthorizationWithToken(Authorization::generateAuthorizationIdForClientCredentialsGrant('test', 'the-client', 'read'), null);
        $authorization->setExpires(new DateTimeImmutable('+10 minutes'));
        $oAuthClient = $this->createMock(OAuthClient::class);
        $oAuthClient->method('getAuthorization')->willReturn($authorization);
        $oAuthClient->expects($this->never())->method('requestAccessToken');
        $this->inject($this->oidcClient, 'oAuthClient', $oAuthClient);

        $accessToken = $this->oidcClient->getAccessToken('test', 'the-client', 'the-secret', 'read');

        static::assertSame($authorization->getAccessToken()->getToken(), $accessToken->getToken());
    }

    #[Test]
    public function getAccessTokenRenewsTokenWithoutExpirationTimeWhenItsAuthorizationExpires(): void
    {
        $authorization = self::createAuthorizationWithToken(Authorization::generateAuthorizationIdForClientCredentialsGrant('test', 'the-client', 'read'), null);
        $authorization->setExpires(new DateTimeImmutable('+10 seconds'));
        $oAuthClient = $this->createMock(OAuthClient::class);
        $oAuthClient->method('getAuthorization')->willReturn($authorization);
        $oAuthClient->expects($this->once())->method('requestAccessToken');
        $this->inject($this->oidcClient, 'oAuthClient', $oAuthClient);

        $this->oidcClient->getAccessToken('test', 'the-client', 'the-secret', 'read');
    }

    private static function createAuthorizationWithToken(string $authorizationId, ?int $expirationTimestamp): Authorization
    {
        $tokenValues = ['access_token' => Algorithms::generateRandomToken(40)];
        if ($expirationTimestamp !== null) {
            $tokenValues['expires'] = $expirationTimestamp;
        }
        $authorization = new Authorization($authorizationId, 'test', 'the-client', Authorization::GRANT_CLIENT_CREDENTIALS, 'read');
        $authorization->setSerializedAccessToken(json_encode(new AccessToken($tokenValues), JSON_THROW_ON_ERROR));
        return $authorization;
    }

    public static function authorizationScopes(): array
    {
        return [
            'empty scope with refresh token' => ['', true, 'openid offline_access'],
            'empty scope without refresh token' => ['', false, 'openid'],
            'custom scope with refresh token' => ['profile email', true, 'profile email openid offline_access'],
            'custom scope without refresh token' => ['profile email', false, 'profile email openid'],
            'duplicate identifiers are removed' => ['openid offline_access', true, 'openid offline_access'],
            'explicit offline_access is kept' => ['profile offline_access', false, 'profile offline_access openid'],
        ];
    }

    #[Test]
    #[DataProvider('authorizationScopes')]
    public function buildAuthorizationScopeAddsRequiredScopeIdentifiers(string $scope, bool $requestRefreshToken, string $expectedScope): void
    {
        $method = new \ReflectionMethod(OpenIdConnectClient::class, 'buildAuthorizationScope');

        static::assertSame($expectedScope, $method->invoke($this->oidcClient, $scope, $requestRefreshToken));
    }

    /**
     * Injects $dependency into property $name of $target
     *
     * This is a convenience method for setting a protected or private property in
     * a test subject for the purpose of injecting a dependency.
     *
     * @param object $target The instance which needs the dependency
     * @param string $name Name of the property to be injected
     * @param mixed $dependency The dependency to inject – usually an object but can also be any other type
     * @return void
     * @throws ReflectionException
     */
    protected function inject($target, $name, $dependency): void
    {
        if (!is_object($target)) {
            throw new \InvalidArgumentException('Wrong type for argument $target, must be object.');
        }

        $objectReflection = new \ReflectionObject($target);
        $methodNamePart = strtoupper($name[0]) . substr($name, 1);
        if ($objectReflection->hasMethod('set' . $methodNamePart)) {
            $methodName = 'set' . $methodNamePart;
            $target->$methodName($dependency);
        } elseif ($objectReflection->hasMethod('inject' . $methodNamePart)) {
            $methodName = 'inject' . $methodNamePart;
            $target->$methodName($dependency);
        } elseif ($objectReflection->hasProperty($name)) {
            $property = $objectReflection->getProperty($name);
            $property->setValue($target, $dependency);
        } else {
            throw new \RuntimeException('Could not inject ' . $name . ' into object of type ' . get_class($target));
        }
    }
}
