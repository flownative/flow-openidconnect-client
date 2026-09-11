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

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

class IdentityTokenTest extends TestCase
{
    public static function invalidJsonStrings(): array
    {
        return [
            ['xy', 1559204596],
            ['abc.def.ghi.foo..', 1559204596],
            ['header.payload.signature.something', 1559208004],
            ['header.payload.signature.=', 1559208004],
            ['ImludmFsaWRfaGVhZGVyIg==.eyJpc3MiOiJodHRwczovL2lkLmV4YW1wbGUuY29tIiwiYXVkIjoiQCFEREQ1LjM3MEQuODU0Ny5GRkQ5ITAwMDEhQTFDOS45MkMxITAwMDghMTNEQi41NEQ4LjY1REUuMjc2MSIsImV4cCI6MTU1OTIwNTU2MCwiaWF0IjoxNTU5MjAxOTYwLCJhdXRoX3RpbWUiOjE1NTkyMDE5NTksImF0X2hhc2giOiJfU1BHdHM1OUlTbFdNSHhzMmEwM3N3Iiwib3hPcGVuSURDb25uZWN0VmVyc2lvbiI6Im9wZW5pZGNvbm5lY3QtMS4wIiwic3ViIjoiVVdBWWZ6em1jYU5BWnlfQzhhOFVvVXhNbWhUMUlsY0tsWEc4VG5Xa3lJTSJ9.VsOdosHuRWVaoacWG1CNJl0IZrHH-HbFTCZDcQDtFPSma13sHO-C69tm_HTjHX5DnMX6B_lDCgu3A8AsSZIQEG71z_Mnd2uxHoUrKUtHr8iM9bhpPKMnaXx9jr0O1EtKAJDLkz4qdzNunyOU7Ud94Lc8YxIjf7FZH_-jJc0UqFyFKY2rdEiZQVATNG94F-SIWA4CK5FZtW47TCL8EPBUzP8gGG8g6eMBEIfv80uWQxpJ59_UB91D8U6zSOiA4JrFDBRLkIX2kGnUZ7eu1G-4O6TglL_Id0oMeJdNEsMARYKHGmYZjvHGFVoLyoxca1KDK5dlcnLsYyxfKsZWNrTaqA', 1559207497],
            ['eyJraWQiOiJkZmViZTVlNy00MjMyLTQ0NjQtOGYyZS0xNTE2ODFhMGQxNzMiLCJ0eXAiOiJKV1QifQ==.eyJpc3MiOiJodHRwczovL2lkLmV4YW1wbGUuY29tIiwiYXVkIjoiQCFEREQ1LjM3MEQuODU0Ny5GRkQ5ITAwMDEhQTFDOS45MkMxITAwMDghMTNEQi41NEQ4LjY1REUuMjc2MSIsImV4cCI6MTU1OTIwNTU2MCwiaWF0IjoxNTU5MjAxOTYwLCJhdXRoX3RpbWUiOjE1NTkyMDE5NTksImF0X2hhc2giOiJfU1BHdHM1OUlTbFdNSHhzMmEwM3N3Iiwib3hPcGVuSURDb25uZWN0VmVyc2lvbiI6Im9wZW5pZGNvbm5lY3QtMS4wIiwic3ViIjoiVVdBWWZ6em1jYU5BWnlfQzhhOFVvVXhNbWhUMUlsY0tsWEc4VG5Xa3lJTSJ9.VsOdosHuRWVaoacWG1CNJl0IZrHH-HbFTCZDcQDtFPSma13sHO-C69tm_HTjHX5DnMX6B_lDCgu3A8AsSZIQEG71z_Mnd2uxHoUrKUtHr8iM9bhpPKMnaXx9jr0O1EtKAJDLkz4qdzNunyOU7Ud94Lc8YxIjf7FZH_-jJc0UqFyFKY2rdEiZQVATNG94F-SIWA4CK5FZtW47TCL8EPBUzP8gGG8g6eMBEIfv80uWQxpJ59_UB91D8U6zSOiA4JrFDBRLkIX2kGnUZ7eu1G-4O6TglL_Id0oMeJdNEsMARYKHGmYZjvHGFVoLyoxca1KDK5dlcnLsYyxfKsZWNrTaqA', 1559212231],
            ['eyJraWQiOiJkZmViZTVlNy00MjMyLTQ0NjQtOGYyZS0xNTE2ODFhMGQxNzMiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.InNvbWV0aGluZyI=.VsOdosHuRWVaoacWG1CNJl0IZrHH-HbFTCZDcQDtFPSma13sHO-C69tm_HTjHX5DnMX6B_lDCgu3A8AsSZIQEG71z_Mnd2uxHoUrKUtHr8iM9bhpPKMnaXx9jr0O1EtKAJDLkz4qdzNunyOU7Ud94Lc8YxIjf7FZH_-jJc0UqFyFKY2rdEiZQVATNG94F-SIWA4CK5FZtW47TCL8EPBUzP8gGG8g6eMBEIfv80uWQxpJ59_UB91D8U6zSOiA4JrFDBRLkIX2kGnUZ7eu1G-4O6TglL_Id0oMeJdNEsMARYKHGmYZjvHGFVoLyoxca1KDK5dlcnLsYyxfKsZWNrTaqA', 1559208043],
        ];
    }

    #[Test]
    #[DataProvider('invalidJsonStrings')]
    public function fromJsonRejectsInvalidJsonStrings(string $json, int $expectedExceptionCode): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionCode($expectedExceptionCode);
        IdentityToken::fromJwt($json);
    }

    /**
     * {"kid":"dfebe5e7-4232-4464-8f2e-151681a0d173","typ":"JWT","alg":"RS256"}
     * {"iss":"https://id.example.com","aud":"@!DDD5.370D.8547.FFD9!0001!A1C9.92C1!0008!13DB.54D8.65DE.2761","exp":1559205560,"iat":1559201960,"auth_time":1559201959,"at_hash":"_SPGts59ISlWMHxs2a03sw","oxOpenIDConnectVersion":"openidconnect-1.0","sub":"UWAYfzzmcaNAZy_C8a8UoUxMmhT1IlcKlXG8TnWkyIM"}
     * … (binary data of signature) …
     */
    #[Test]
    public function fromJsonSetsValuesCorrectly(): void
    {
        $json = 'eyJraWQiOiJkZmViZTVlNy00MjMyLTQ0NjQtOGYyZS0xNTE2ODFhMGQxNzMiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lkLmV4YW1wbGUuY29tIiwiYXVkIjoiQCFEREQ1LjM3MEQuODU0Ny5GRkQ5ITAwMDEhQTFDOS45MkMxITAwMDghMTNEQi41NEQ4LjY1REUuMjc2MSIsImV4cCI6MTU1OTIwNTU2MCwiaWF0IjoxNTU5MjAxOTYwLCJhdXRoX3RpbWUiOjE1NTkyMDE5NTksImF0X2hhc2giOiJfU1BHdHM1OUlTbFdNSHhzMmEwM3N3Iiwib3hPcGVuSURDb25uZWN0VmVyc2lvbiI6Im9wZW5pZGNvbm5lY3QtMS4wIiwic3ViIjoiVVdBWWZ6em1jYU5BWnlfQzhhOFVvVXhNbWhUMUlsY0tsWEc4VG5Xa3lJTSJ9.VsOdosHuRWVaoacWG1CNJl0IZrHH-HbFTCZDcQDtFPSma13sHO-C69tm_HTjHX5DnMX6B_lDCgu3A8AsSZIQEG71z_Mnd2uxHoUrKUtHr8iM9bhpPKMnaXx9jr0O1EtKAJDLkz4qdzNunyOU7Ud94Lc8YxIjf7FZH_-jJc0UqFyFKY2rdEiZQVATNG94F-SIWA4CK5FZtW47TCL8EPBUzP8gGG8g6eMBEIfv80uWQxpJ59_UB91D8U6zSOiA4JrFDBRLkIX2kGnUZ7eu1G-4O6TglL_Id0oMeJdNEsMARYKHGmYZjvHGFVoLyoxca1KDK5dlcnLsYyxfKsZWNrTaqA';
        $identityToken = IdentityToken::fromJwt($json);

        static::assertSame('https://id.example.com', $identityToken->values['iss']);
        static::assertSame('UWAYfzzmcaNAZy_C8a8UoUxMmhT1IlcKlXG8TnWkyIM', $identityToken->values['sub']);
        static::assertSame('@!DDD5.370D.8547.FFD9!0001!A1C9.92C1!0008!13DB.54D8.65DE.2761', $identityToken->values['aud']);
    }

    #[Test]
    public function asJwtReturnsTokenAsString(): void
    {
        $json = 'eyJraWQiOiJkZmViZTVlNy00MjMyLTQ0NjQtOGYyZS0xNTE2ODFhMGQxNzMiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lkLmV4YW1wbGUuY29tIiwiYXVkIjoiQCFEREQ1LjM3MEQuODU0Ny5GRkQ5ITAwMDEhQTFDOS45MkMxITAwMDghMTNEQi41NEQ4LjY1REUuMjc2MSIsImV4cCI6MTU1OTIwNTU2MCwiaWF0IjoxNTU5MjAxOTYwLCJhdXRoX3RpbWUiOjE1NTkyMDE5NTksImF0X2hhc2giOiJfU1BHdHM1OUlTbFdNSHhzMmEwM3N3Iiwib3hPcGVuSURDb25uZWN0VmVyc2lvbiI6Im9wZW5pZGNvbm5lY3QtMS4wIiwic3ViIjoiVVdBWWZ6em1jYU5BWnlfQzhhOFVvVXhNbWhUMUlsY0tsWEc4VG5Xa3lJTSJ9.VsOdosHuRWVaoacWG1CNJl0IZrHH-HbFTCZDcQDtFPSma13sHO-C69tm_HTjHX5DnMX6B_lDCgu3A8AsSZIQEG71z_Mnd2uxHoUrKUtHr8iM9bhpPKMnaXx9jr0O1EtKAJDLkz4qdzNunyOU7Ud94Lc8YxIjf7FZH_-jJc0UqFyFKY2rdEiZQVATNG94F-SIWA4CK5FZtW47TCL8EPBUzP8gGG8g6eMBEIfv80uWQxpJ59_UB91D8U6zSOiA4JrFDBRLkIX2kGnUZ7eu1G-4O6TglL_Id0oMeJdNEsMARYKHGmYZjvHGFVoLyoxca1KDK5dlcnLsYyxfKsZWNrTaqA';
        $identityToken = IdentityToken::fromJwt($json);
        static::assertSame($identityToken->asJwt(), $json);
        static::assertSame((string)$identityToken, $json);
    }

    #[Test]
    public function isExpiredAtReturnsCorrectResult(): void
    {
        $json = 'eyJraWQiOiJkZmViZTVlNy00MjMyLTQ0NjQtOGYyZS0xNTE2ODFhMGQxNzMiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lkLmV4YW1wbGUuY29tIiwiYXVkIjoiQCFEREQ1LjM3MEQuODU0Ny5GRkQ5ITAwMDEhQTFDOS45MkMxITAwMDghMTNEQi41NEQ4LjY1REUuMjc2MSIsImV4cCI6MTU1OTIwNTU2MCwiaWF0IjoxNTU5MjAxOTYwLCJhdXRoX3RpbWUiOjE1NTkyMDE5NTksImF0X2hhc2giOiJfU1BHdHM1OUlTbFdNSHhzMmEwM3N3Iiwib3hPcGVuSURDb25uZWN0VmVyc2lvbiI6Im9wZW5pZGNvbm5lY3QtMS4wIiwic3ViIjoiVVdBWWZ6em1jYU5BWnlfQzhhOFVvVXhNbWhUMUlsY0tsWEc4VG5Xa3lJTSJ9.VsOdosHuRWVaoacWG1CNJl0IZrHH-HbFTCZDcQDtFPSma13sHO-C69tm_HTjHX5DnMX6B_lDCgu3A8AsSZIQEG71z_Mnd2uxHoUrKUtHr8iM9bhpPKMnaXx9jr0O1EtKAJDLkz4qdzNunyOU7Ud94Lc8YxIjf7FZH_-jJc0UqFyFKY2rdEiZQVATNG94F-SIWA4CK5FZtW47TCL8EPBUzP8gGG8g6eMBEIfv80uWQxpJ59_UB91D8U6zSOiA4JrFDBRLkIX2kGnUZ7eu1G-4O6TglL_Id0oMeJdNEsMARYKHGmYZjvHGFVoLyoxca1KDK5dlcnLsYyxfKsZWNrTaqA';
        $identityToken = IdentityToken::fromJwt($json);

        # Token expired at 2019-05-30 08:39:20.000000
        static::assertFalse($identityToken->isExpiredAt(\DateTimeImmutable::createFromFormat('d.m.Y H:i:s', '29.05.2019 09:00:00')));
        static::assertTrue($identityToken->isExpiredAt(\DateTimeImmutable::createFromFormat('d.m.Y H:i:s', '31.05.2019 09:00:00')));
    }

    #[Test]
    public function isExpiredAtTreatsTokenWithoutExpirationTimeAsExpired(): void
    {
        $identityToken = IdentityToken::fromJwt(self::createUnsignedJwt(['iss' => 'https://id.example.com', 'sub' => 'subject']));

        static::assertTrue($identityToken->isExpiredAt(new \DateTimeImmutable('2000-01-01')));
    }

    public static function notYetValidClaims(): array
    {
        $now = 1789000000;
        return [
            'no time claims' => [[], $now, false],
            'issued in the past' => [['iat' => $now - 10], $now, false],
            'issued now' => [['iat' => $now], $now, false],
            'issued in the future' => [['iat' => $now + 10], $now, true],
            'valid since the past' => [['nbf' => $now - 10], $now, false],
            'valid in the future' => [['nbf' => $now + 10], $now, true],
        ];
    }

    #[Test]
    #[DataProvider('notYetValidClaims')]
    public function isNotYetValidAtChecksIssuedAtAndNotBefore(array $claims, int $now, bool $expectedResult): void
    {
        $identityToken = IdentityToken::fromJwt(self::createUnsignedJwt(array_merge(['sub' => 'subject', 'exp' => $now + 3600], $claims)));

        static::assertSame($expectedResult, $identityToken->isNotYetValidAt(new \DateTimeImmutable('@' . $now)));
    }

    #[Test]
    public function isIssuedByComparesIssuerStrictly(): void
    {
        $identityToken = IdentityToken::fromJwt(self::createUnsignedJwt(['iss' => 'https://id.example.com/', 'sub' => 'subject']));

        static::assertTrue($identityToken->isIssuedBy('https://id.example.com/'));
        static::assertFalse($identityToken->isIssuedBy('https://id.example.com'));
    }

    #[Test]
    public function fromJwtRejectsUnparseableTimeClaims(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionCode(1789122174);
        IdentityToken::fromJwt(self::createUnsignedJwt(['sub' => 'subject', 'exp' => 'tomorrow']));
    }

    public static function invalidTimeClaimTypes(): array
    {
        return [
            'null' => [null],
            'boolean' => [true],
            'list' => [[1789000000]],
            'object' => [['time' => 1789000000]],
        ];
    }

    #[Test]
    #[DataProvider('invalidTimeClaimTypes')]
    public function fromJwtRejectsTimeClaimsOfInvalidType(mixed $expirationTime): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionCode(1789122174);
        IdentityToken::fromJwt(self::createUnsignedJwt(['sub' => 'subject', 'exp' => $expirationTime]));
    }

    #[Test]
    public function fromJwtRejectsPartsWhichCannotBeDecodedStrictly(): void
    {
        [, $claims, $signature] = explode('.', self::createUnsignedJwt(['sub' => 'subject', 'exp' => 1789000000]));

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionCode(1789122174);
        IdentityToken::fromJwt('eyJhbGciOiJSUzI1NiIgfQ==.' . $claims . '.' . $signature);
    }

    #[Test]
    public function fromJwtRejectsCriticalHeaderExtensions(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionCode(1789123616);
        IdentityToken::fromJwt(self::createUnsignedJwt(['sub' => 'subject'], ['typ' => 'JWT', 'alg' => 'RS256', 'crit' => ['b64'], 'b64' => false]));
    }

    public static function audiences(): array
    {
        return [
            'single audience, matching' => ['client-a', 'client-a', true],
            'single audience, not matching' => ['client-b', 'client-a', false],
            'multiple audiences, matching' => [['client-a', 'client-b'], 'client-b', true],
            'multiple audiences, not matching' => [['client-a', 'client-b'], 'client-c', false],
            'empty list of audiences' => [[], 'client-a', false],
            'numeric audience compared strictly' => [['1e3'], '1000', false],
            'no audience' => [null, 'client-a', false],
            'object instead of list' => [['x' => 'client-a'], 'client-a', false],
        ];
    }

    #[Test]
    #[DataProvider('audiences')]
    public function audienceContainsSupportsSingleAndMultipleAudiences(string|array|null $audienceClaim, string $audience, bool $expectedResult): void
    {
        $values = ['iss' => 'https://id.example.com', 'sub' => 'subject'];
        if ($audienceClaim !== null) {
            $values['aud'] = $audienceClaim;
        }
        $identityToken = IdentityToken::fromJwt(self::createUnsignedJwt($values));

        static::assertSame($expectedResult, $identityToken->audienceContains($audience));
    }

    private static function createUnsignedJwt(array $values, array $header = ['typ' => 'JWT', 'alg' => 'RS256']): string
    {
        $encode = static fn (string $data): string => rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
        return $encode(json_encode($header)) . '.' . $encode(json_encode($values)) . '.' . $encode('signature');
    }
}
