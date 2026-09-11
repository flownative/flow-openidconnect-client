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

use Flownative\OpenIdConnect\Client\Authentication\TokenArguments;
use Flownative\OpenIdConnect\Client\Tests\Unit\Fixtures\OpenIdConnectClientFixture;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

class TokenArgumentsTest extends TestCase
{
    #[Test]
    public function signedStringCanBeConvertedBackToTokenArguments(): void
    {
        $hashService = OpenIdConnectClientFixture::createHashService();
        $signedString = (string)TokenArguments::fromArray([TokenArguments::SERVICE_NAME => 'test', TokenArguments::AUTHORIZATION_ID => 'authorization-1'], $hashService);

        $tokenArguments = TokenArguments::fromSignedString($signedString, $hashService);

        static::assertSame('test', $tokenArguments[TokenArguments::SERVICE_NAME]);
        static::assertSame('authorization-1', $tokenArguments[TokenArguments::AUTHORIZATION_ID]);
    }

    #[Test]
    public function fromSignedStringRejectsModifiedPayload(): void
    {
        $hashService = OpenIdConnectClientFixture::createHashService();
        $signedString = (string)TokenArguments::fromArray([TokenArguments::SERVICE_NAME => 'test'], $hashService);
        $modifiedString = base64_encode(str_replace('"test"', '"evil"', base64_decode($signedString)));

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionCode(1560165515);
        TokenArguments::fromSignedString($modifiedString, $hashService);
    }

    #[Test]
    public function fromSignedStringRejectsPayloadWhichIsNotAnArray(): void
    {
        $hashService = OpenIdConnectClientFixture::createHashService();
        $signedString = base64_encode($hashService->appendHmac('"just a string"'));

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionCode(1560162452);
        TokenArguments::fromSignedString($signedString, $hashService);
    }

    #[Test]
    public function fromArrayRejectsUnknownArguments(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionCode(1560162220);
        TokenArguments::fromArray(['role' => 'Administrator'], OpenIdConnectClientFixture::createHashService());
    }

    #[Test]
    public function unsetRemovesArgument(): void
    {
        $tokenArguments = TokenArguments::fromArray([TokenArguments::SERVICE_NAME => 'test'], OpenIdConnectClientFixture::createHashService());
        unset($tokenArguments[TokenArguments::SERVICE_NAME]);

        static::assertFalse(isset($tokenArguments[TokenArguments::SERVICE_NAME]));
        static::assertNull($tokenArguments[TokenArguments::SERVICE_NAME]);
    }
}
