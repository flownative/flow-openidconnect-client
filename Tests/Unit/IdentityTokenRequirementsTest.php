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

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

class IdentityTokenRequirementsTest extends TestCase
{
    public static function invalidArguments(): array
    {
        return [
            'no issuer' => [['issuers' => []], 1791540854],
            'empty issuer' => [['issuers' => ['']], 1791540854],
            'issuer which is not a string' => [['issuers' => [42]], 1791540854],
            'issuers which are no list' => [['issuers' => ['a' => 'https://id.example.com/']], 1791540854],
            'no audience' => [['audiences' => []], 1791540855],
            'empty audience' => [['audiences' => ['']], 1791540855],
            'empty authorized party' => [['authorizedParty' => ''], 1791540856],
            'empty account identifier claim name' => [['accountIdentifierClaimName' => ''], 1791540857],
            'negative leeway' => [['leeway' => -1], 1791540858],
            'empty nonce' => [['nonce' => ''], 1791540859],
        ];
    }

    #[Test]
    #[DataProvider('invalidArguments')]
    public function constructorRejectsInvalidArguments(array $arguments, int $expectedExceptionCode): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionCode($expectedExceptionCode);
        new IdentityTokenRequirements(...array_merge(['issuers' => ['https://id.example.com/'], 'audiences' => ['the-client'], 'authorizedParty' => 'the-client'], $arguments));
    }

    #[Test]
    public function constructorUsesDefaultsForIdentityTokensOfThisClient(): void
    {
        $requirements = new IdentityTokenRequirements(['https://id.example.com/'], ['the-client'], 'the-client');

        static::assertSame('sub', $requirements->accountIdentifierClaimName);
        static::assertTrue($requirements->requireVerifiedEmail);
        static::assertSame(60, $requirements->leeway);
        static::assertNull($requirements->nonce);
    }
}
