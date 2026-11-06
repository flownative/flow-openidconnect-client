<?php
declare(strict_types=1);

namespace Flownative\OpenIdConnect\Client\Tests\Unit\Fixtures;

/*
 * This file is part of the Flownative.OpenIdConnect.Client package.
 *
 * (c) Robert Lemke, Flownative GmbH - www.flownative.com
 *
 * This package is Open Source Software. For the full copyright and license
 * information, please view the LICENSE file which was distributed with this
 * source code.
 */

use Flownative\OpenIdConnect\Client\OAuthClient;

/**
 * The OAuth client of the OpenID Connect client, as it runs in a request to the given host, without Flow's router
 */
class OAuthClientOfHost extends OAuthClient
{
    public function __construct(string $serviceName, private readonly string $finishAuthorizationUri)
    {
        parent::__construct($serviceName);
    }

    public function renderFinishAuthorizationUri(): string
    {
        return $this->finishAuthorizationUri;
    }
}
