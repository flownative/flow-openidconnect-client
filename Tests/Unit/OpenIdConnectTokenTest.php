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

use Flownative\OAuth2\Client\Authorization;
use Flownative\OpenIdConnect\Client\Authentication\OpenIdConnectToken;
use Flownative\OpenIdConnect\Client\Authentication\TokenArguments;
use Flownative\OpenIdConnect\Client\Tests\Unit\Fixtures\OpenIdConnectClientFixture;
use GuzzleHttp\Psr7\ServerRequest;
use League\OAuth2\Client\Token\AccessToken;
use Neos\Flow\Mvc\ActionRequest;
use Neos\Flow\Security\Authentication\TokenInterface;
use Neos\Flow\Security\Cryptography\HashService;
use Neos\Flow\Security\Exception\AccessDeniedException;
use Neos\Flow\Security\Exception\AuthenticationRequiredException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;

class OpenIdConnectTokenTest extends TestCase
{
    private const string COOKIE_NAME = 'flownative_oidc_jwt';
    private const string AUTHORIZATION_ID = 'oidc-test-4c1b7a0e-6f0c-4f7e-9d59-2d3a8c1f5e21';

    #[Test]
    public function updateCredentialsResetsAuthenticationStatus(): void
    {
        $token = new OpenIdConnectToken();
        $token->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);

        $token->updateCredentials(self::createActionRequest());

        static::assertSame(TokenInterface::AUTHENTICATION_NEEDED, $token->getAuthenticationStatus());
    }

    #[Test]
    public function extractIdentityTokenFromRequestReadsBearerTokenFromAuthorizationHeader(): void
    {
        $jwt = self::createUnsignedJwt(['sub' => 'header-subject']);
        $token = new OpenIdConnectToken();
        $token->updateCredentials(self::createActionRequest(headers: ['Authorization' => 'Bearer ' . $jwt]));

        static::assertSame($jwt, $token->extractIdentityTokenFromRequest(self::COOKIE_NAME)->asJwt());
    }

    #[Test]
    public function extractIdentityTokenFromRequestPrefersAuthorizationHeaderOverCookie(): void
    {
        $headerJwt = self::createUnsignedJwt(['sub' => 'header-subject']);
        $token = new OpenIdConnectToken();
        $token->updateCredentials(self::createActionRequest(
            headers: ['Authorization' => 'Bearer ' . $headerJwt],
            cookies: [self::COOKIE_NAME => self::createUnsignedJwt(['sub' => 'cookie-subject'])]
        ));

        static::assertSame('header-subject', $token->extractIdentityTokenFromRequest(self::COOKIE_NAME)->values['sub']);
    }

    #[Test]
    public function extractIdentityTokenFromRequestRejectsMalformedBearerToken(): void
    {
        $token = new OpenIdConnectToken();
        $token->updateCredentials(self::createActionRequest(headers: ['Authorization' => 'Bearer not-a-jwt']));

        try {
            $token->extractIdentityTokenFromRequest(self::COOKIE_NAME);
            static::fail('Expected an AccessDeniedException');
        } catch (AccessDeniedException $exception) {
            static::assertSame(1589283968, $exception->getCode());
        }
        static::assertSame(TokenInterface::WRONG_CREDENTIALS, $token->getAuthenticationStatus());
    }

    #[Test]
    public function extractIdentityTokenFromRequestRejectsAuthorizationHeaderNotStartingWithBearer(): void
    {
        $token = new OpenIdConnectToken();
        $token->updateCredentials(self::createActionRequest(headers: ['Authorization' => 'Token Bearer ' . self::createUnsignedJwt(['sub' => 'subject'])]));

        try {
            $token->extractIdentityTokenFromRequest(self::COOKIE_NAME);
            static::fail('Expected an AuthenticationRequiredException');
        } catch (AuthenticationRequiredException $exception) {
            static::assertSame(1589283608, $exception->getCode());
        }
        static::assertSame(TokenInterface::NO_CREDENTIALS_GIVEN, $token->getAuthenticationStatus());
    }

    #[Test]
    public function extractIdentityTokenFromRequestReadsTokenFromCookie(): void
    {
        $jwt = self::createUnsignedJwt(['sub' => 'cookie-subject']);
        $token = new OpenIdConnectToken();
        $token->updateCredentials(self::createActionRequest(cookies: [self::COOKIE_NAME => $jwt]));

        static::assertSame($jwt, $token->extractIdentityTokenFromRequest(self::COOKIE_NAME)->asJwt());
    }

    #[Test]
    public function extractIdentityTokenFromRequestIgnoresNonBearerAuthorizationHeader(): void
    {
        $jwt = self::createUnsignedJwt(['sub' => 'cookie-subject']);
        $token = new OpenIdConnectToken();
        $token->updateCredentials(self::createActionRequest(
            headers: ['Authorization' => 'Basic dXNlcjpwYXNzd29yZA=='],
            cookies: [self::COOKIE_NAME => $jwt]
        ));

        static::assertSame($jwt, $token->extractIdentityTokenFromRequest(self::COOKIE_NAME)->asJwt());
    }

    #[Test]
    public function extractIdentityTokenFromRequestRequiresAuthenticationIfCookieIsMissing(): void
    {
        $token = new OpenIdConnectToken();
        $token->updateCredentials(self::createActionRequest(cookies: ['some_other_cookie' => 'value']));

        try {
            $token->extractIdentityTokenFromRequest(self::COOKIE_NAME);
            static::fail('Expected an AuthenticationRequiredException');
        } catch (AuthenticationRequiredException $exception) {
            static::assertSame(1560349409, $exception->getCode());
        }
        static::assertSame(TokenInterface::NO_CREDENTIALS_GIVEN, $token->getAuthenticationStatus());
    }

    #[Test]
    public function extractIdentityTokenFromRequestRequiresAuthenticationIfCookieContainsNoJwt(): void
    {
        $token = new OpenIdConnectToken();
        $token->updateCredentials(self::createActionRequest(cookies: [self::COOKIE_NAME => 'not-a-jwt']));

        try {
            $token->extractIdentityTokenFromRequest(self::COOKIE_NAME);
            static::fail('Expected an AuthenticationRequiredException');
        } catch (AuthenticationRequiredException $exception) {
            static::assertSame(1560349541, $exception->getCode());
        }
        static::assertSame(TokenInterface::WRONG_CREDENTIALS, $token->getAuthenticationStatus());
    }

    #[Test]
    public function extractIdentityTokenFromRequestDeniesAccessIfAuthorizationIdentifierIsMissing(): void
    {
        $token = new OpenIdConnectToken();
        $token->updateCredentials(self::createActionRequest(queryParameters: [OpenIdConnectToken::OIDC_PARAMETER_NAME => 'signed-arguments']));

        $this->expectException(AccessDeniedException::class);
        $this->expectExceptionCode(1560350311);
        $token->extractIdentityTokenFromRequest(self::COOKIE_NAME);
    }

    #[Test]
    public function extractIdentityTokenFromRequestUsesTokensOfFinishedAuthorization(): void
    {
        $hashService = OpenIdConnectClientFixture::createHashService();
        $jwt = self::createUnsignedJwt(['sub' => 'returning-subject']);
        $authorization = new Authorization(self::AUTHORIZATION_ID, 'oidc', OpenIdConnectClientFixture::CLIENT_ID, Authorization::GRANT_AUTHORIZATION_CODE, 'openid');
        $authorization->setSerializedAccessToken(json_encode(new AccessToken(['access_token' => 'the-access-token', 'refresh_token' => 'the-refresh-token', 'id_token' => $jwt]), JSON_THROW_ON_ERROR));

        $oAuthClient = $this->createMock(OAuthClient::class);
        $oAuthClient->method('getAuthorization')->willReturnMap([[self::AUTHORIZATION_ID, $authorization]]);
        $oAuthClient->expects($this->once())->method('removeAuthorization')->with(self::AUTHORIZATION_ID);

        $token = $this->createTokenWithClient($oAuthClient, $hashService);
        $token->updateCredentials(self::createActionRequest(queryParameters: self::createReturnQueryParameters($hashService)));

        static::assertSame($jwt, $token->extractIdentityTokenFromRequest(self::COOKIE_NAME)->asJwt());
        static::assertSame('the-refresh-token', $token->getRefreshToken());
    }

    #[Test]
    public function extractIdentityTokenFromRequestDeniesAccessIfAuthorizationDoesNotExist(): void
    {
        $hashService = OpenIdConnectClientFixture::createHashService();
        $oAuthClient = $this->createStub(OAuthClient::class);
        $oAuthClient->method('getAuthorization')->willReturn(null);

        $token = $this->createTokenWithClient($oAuthClient, $hashService);
        $token->updateCredentials(self::createActionRequest(queryParameters: self::createReturnQueryParameters($hashService)));

        $this->expectException(AccessDeniedException::class);
        $this->expectExceptionCode(1560350413);
        $token->extractIdentityTokenFromRequest(self::COOKIE_NAME);
    }

    #[Test]
    public function extractIdentityTokenFromRequestDeniesAccessIfTokenArgumentsWereModified(): void
    {
        $hashService = OpenIdConnectClientFixture::createHashService();
        $queryParameters = self::createReturnQueryParameters($hashService);
        $queryParameters[OpenIdConnectToken::OIDC_PARAMETER_NAME] = base64_encode(str_replace('"test"', '"evil"', base64_decode($queryParameters[OpenIdConnectToken::OIDC_PARAMETER_NAME])));

        $token = $this->createTokenWithClient($this->createStub(OAuthClient::class), $hashService);
        $token->updateCredentials(self::createActionRequest(queryParameters: $queryParameters));

        try {
            $token->extractIdentityTokenFromRequest(self::COOKIE_NAME);
            static::fail('Expected an AccessDeniedException');
        } catch (AccessDeniedException $exception) {
            static::assertSame(1560349658, $exception->getCode());
        }
        static::assertSame(TokenInterface::WRONG_CREDENTIALS, $token->getAuthenticationStatus());
    }

    #[Test]
    public function extractIdentityTokenFromRequestDeniesAccessIfQueryParametersAreNotStrings(): void
    {
        $hashService = OpenIdConnectClientFixture::createHashService();
        $queryParameters = self::createReturnQueryParameters($hashService);
        $queryParameters[OpenIdConnectToken::OIDC_PARAMETER_NAME] = [$queryParameters[OpenIdConnectToken::OIDC_PARAMETER_NAME]];

        $token = $this->createTokenWithClient($this->createStub(OAuthClient::class), $hashService);
        $token->updateCredentials(self::createActionRequest(queryParameters: $queryParameters));

        try {
            $token->extractIdentityTokenFromRequest(self::COOKIE_NAME);
            static::fail('Expected an AccessDeniedException');
        } catch (AccessDeniedException $exception) {
            static::assertSame(1789122178, $exception->getCode());
        }
        static::assertSame(TokenInterface::WRONG_CREDENTIALS, $token->getAuthenticationStatus());
    }

    #[Test]
    public function extractIdentityTokenFromRequestDeniesAccessIfClientCannotBeCreated(): void
    {
        $hashService = OpenIdConnectClientFixture::createHashService();
        $clientFactory = $this->createStub(OpenIdConnectClientFactory::class);
        $clientFactory->method('create')->willThrowException(new ConnectionException('OpenID Connect Client: Failed discovering options', 1554902567));
        $token = new OpenIdConnectToken();
        OpenIdConnectClientFixture::inject($token, 'openIdConnectClientFactory', $clientFactory);
        OpenIdConnectClientFixture::inject($token, 'hashService', $hashService);
        $token->updateCredentials(self::createActionRequest(queryParameters: self::createReturnQueryParameters($hashService)));

        $this->expectException(AccessDeniedException::class);
        $this->expectExceptionCode(1560350413);
        $token->extractIdentityTokenFromRequest(self::COOKIE_NAME);
    }

    private function createTokenWithClient(OAuthClient $oAuthClient, HashService $hashService): OpenIdConnectToken
    {
        $client = OpenIdConnectClientFixture::createClient($oAuthClient, $hashService, $this->createStub(LoggerInterface::class));
        $clientFactory = $this->createStub(OpenIdConnectClientFactory::class);
        $clientFactory->method('create')->willReturn($client);

        $token = new OpenIdConnectToken();
        OpenIdConnectClientFixture::inject($token, 'openIdConnectClientFactory', $clientFactory);
        OpenIdConnectClientFixture::inject($token, 'hashService', $hashService);
        return $token;
    }

    private static function createReturnQueryParameters(HashService $hashService): array
    {
        return [
            OpenIdConnectToken::OIDC_PARAMETER_NAME => (string)TokenArguments::fromArray([TokenArguments::SERVICE_NAME => OpenIdConnectClientFixture::SERVICE_NAME], $hashService),
            OAuthClient::generateAuthorizationIdQueryParameterName(OAuthClient::SERVICE_TYPE) => self::AUTHORIZATION_ID,
        ];
    }

    private static function createActionRequest(array $headers = [], array $cookies = [], array $queryParameters = []): ActionRequest
    {
        $httpRequest = (new ServerRequest('GET', 'https://www.example.com/', $headers))
            ->withCookieParams($cookies)
            ->withQueryParams($queryParameters);
        return ActionRequest::fromHttpRequest($httpRequest);
    }

    private static function createUnsignedJwt(array $values): string
    {
        $encode = static fn (string $data): string => rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
        return $encode(json_encode(['typ' => 'JWT', 'alg' => 'RS256'])) . '.' . $encode(json_encode($values)) . '.' . $encode('signature');
    }
}
