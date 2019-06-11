<?php
declare(strict_types = 1);
namespace Flownative\OpenIdConnect\Client\Authentication;

use Flownative\OpenIdConnect\Client\ConnectionException;
use Flownative\OpenIdConnect\Client\OAuthClient;
use Flownative\OpenIdConnect\Client\OpenIdConnectClient;
use Flownative\OpenIdConnect\Client\ServiceException;
use Neos\Flow\Http\Component\ComponentContext;
use Neos\Flow\Http\Component\ComponentInterface;
use Neos\Flow\Http\Cookie;
use Neos\Flow\Http\Request;

final class OpenIdConnectHttpComponent implements ComponentInterface
{
    /**
     * @param ComponentContext $componentContext
     * @throws ConnectionException
     * @throws ServiceException
     * @throws \Exception
     */
    public function handle(ComponentContext $componentContext): void
    {
        $request = $componentContext->getHttpRequest();
        $response = $componentContext->getHttpResponse();
        assert($request instanceof Request);

        $query = $request->getQueryParams();
        if (!isset($query[OAuthClient::STATE_QUERY_PARAMETER_NAME]) || empty($query[OAuthClient::STATE_QUERY_PARAMETER_NAME])) {
            return;
        }

        $stateIdentifier = $query[OAuthClient::STATE_QUERY_PARAMETER_NAME];

        // FIXME: Hardcoded service name
        $client = new OpenIdConnectClient('cornelsen');
        $identityToken = $client->getIdentityToken($stateIdentifier);
        if ($identityToken === null) {
            return;
        }

        $componentContext->replaceHttpRequest(
            $request->withCookieParams([
                OpenIdConnectToken::JWT_COOKIE_NAME => (string)$identityToken
            ])
        );

        $componentContext->replaceHttpResponse(
            $response->withHeader('Set-Cookie', (string)new Cookie(OpenIdConnectToken::JWT_COOKIE_NAME, $identityToken->asJwt(), $identityToken->values['exp'], null, null, '/', true, true))
        );
    }
}
