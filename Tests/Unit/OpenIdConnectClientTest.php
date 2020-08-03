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

use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Neos\Cache\Backend\TransientMemoryBackend;
use Neos\Cache\Frontend\VariableFrontend;
use Neos\Flow\Tests\UnitTestCase;
use Psr\Http\Message\StreamInterface;

class OpenIdConnectClientTest extends UnitTestCase
{
    /**
     * @var OpenIdConnectClient
     */
    protected $oidcClient;

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

        $this->oidcClient = new OpenIdConnectClient('test');
        $this->inject($this->oidcClient, 'discoveryCache', $this->discoveryCache);
        $this->inject($this->oidcClient, 'jwksCache', $this->jwksCache);
    }

    /**
     * @test
     * @throws
     */
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

        $mockHttpClient->expects($this->once())->method('request')->with('GET', $this->settings['services']['test']['options']['jwksUri'])->willReturn($mockHttpResponse);
        $mockHttpResponse->expects($this->once())->method('getBody')->willReturn($mockHttpBody);
        $mockHttpBody->expects($this->once())->method('getContents')->willReturn(json_encode(['keys' => json_decode($this->exampleJwksJson, true, 512, JSON_THROW_ON_ERROR)], JSON_THROW_ON_ERROR, 512));

        $actualJwks = $this->oidcClient->getJwks();

        $this->assertSame($expectedJwks, $actualJwks);
        $this->assertSame($expectedJwks, $this->jwksCache->get($cacheEntryIdentifier));
    }

    /**
     * @test
     * @throws
     */
    public function getJwksThrowsExceptionOnFailedDiscoveryRequest(): void
    {
        $mockHttpClient = $this->createMock(HttpClient::class);
        $mockHttpRequest = $this->createMock(Request::class);

        $this->inject($this->oidcClient, 'settings', $this->settings);
        $this->inject($this->oidcClient, 'httpClient', $mockHttpClient);
        $this->oidcClient->initializeObject();

        $mockHttpClient->expects($this->once())->method('request')->willThrowException(new ConnectException('Something wrong', $mockHttpRequest));

        $this->expectExceptionCode(1559211266);
        $this->oidcClient->getJwks();
    }

    /**
     * @test
     * @throws
     */
    public function getJwksThrowsExceptionOnMalformedResponseFromDiscoveryService(): void
    {
        $mockHttpClient = $this->createMock(HttpClient::class);
        $mockHttpResponse = $this->createMock(Response::class);
        $mockHttpBody = $this->createMock(StreamInterface::class);

        $this->inject($this->oidcClient, 'settings', $this->settings);
        $this->inject($this->oidcClient, 'httpClient', $mockHttpClient);
        $this->oidcClient->initializeObject();

        $mockHttpClient->expects($this->once())->method('request')->with('GET', $this->settings['services']['test']['options']['jwksUri'])->willReturn($mockHttpResponse);
        $mockHttpResponse->expects($this->once())->method('getBody')->willReturn($mockHttpBody);
        $mockHttpBody->expects($this->once())->method('getContents')->willReturn(json_encode(['something invalid' => json_decode($this->exampleJwksJson, true, 512, JSON_THROW_ON_ERROR)], JSON_THROW_ON_ERROR, 512));

        $this->expectExceptionCode(1559211340);
        $this->oidcClient->getJwks();
    }

    /**
     * @test
     * @throws
     */
    public function getJwksReturnsJwksFromCacheIfItExists(): void
    {
        $this->inject($this->oidcClient, 'settings', $this->settings);
        $this->oidcClient->initializeObject();

        $expectedJwks = json_decode($this->exampleJwksJson, true, 512, JSON_THROW_ON_ERROR);
        $cacheEntryIdentifier = sha1($this->settings['services']['test']['options']['jwksUri']);
        $this->jwksCache->set($cacheEntryIdentifier, $expectedJwks);

        $this->assertSame($expectedJwks, $this->oidcClient->getJwks());
    }
}
