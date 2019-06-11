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

use PHPUnit\Framework\TestCase;

class IdentityTokenTest extends TestCase
{
    /**
     * @return array
     */
    public function invalidJsonStrings(): array
    {
        return [
            ['xy'],
            ['abc.def.ghi.foo..']
        ];
    }


    /**
     * @test
     * @dataProvider invalidJsonStrings
     * @expectedException \InvalidArgumentException
     * @return void
     */
    public function fromJsonRejectsInvalidJsonStrings($json): void
    {
        IdentityToken::fromJwt($json);

    }

    /**
     * {"kid":"dfebe5e7-4232-4464-8f2e-151681a0d173","typ":"JWT","alg":"RS256"}
     * {"iss":"https://id.example.com","aud":"@!DDD5.370D.8547.FFD9!0001!A1C9.92C1!0008!13DB.54D8.65DE.2761","exp":1559205560,"iat":1559201960,"auth_time":1559201959,"at_hash":"_SPGts59ISlWMHxs2a03sw","oxOpenIDConnectVersion":"openidconnect-1.0","sub":"UWAYfzzmcaNAZy_C8a8UoUxMmhT1IlcKlXG8TnWkyIM"}
     *
     * @test
     * @return void
     */
    public function fromJsonSetsValuesCorrectly(): void
    {
        $json = 'eyJraWQiOiJkZmViZTVlNy00MjMyLTQ0NjQtOGYyZS0xNTE2ODFhMGQxNzMiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lkLmV4YW1wbGUuY29tIiwiYXVkIjoiQCFEREQ1LjM3MEQuODU0Ny5GRkQ5ITAwMDEhQTFDOS45MkMxITAwMDghMTNEQi41NEQ4LjY1REUuMjc2MSIsImV4cCI6MTU1OTIwNTU2MCwiaWF0IjoxNTU5MjAxOTYwLCJhdXRoX3RpbWUiOjE1NTkyMDE5NTksImF0X2hhc2giOiJfU1BHdHM1OUlTbFdNSHhzMmEwM3N3Iiwib3hPcGVuSURDb25uZWN0VmVyc2lvbiI6Im9wZW5pZGNvbm5lY3QtMS4wIiwic3ViIjoiVVdBWWZ6em1jYU5BWnlfQzhhOFVvVXhNbWhUMUlsY0tsWEc4VG5Xa3lJTSJ9.VsOdosHuRWVaoacWG1CNJl0IZrHH-HbFTCZDcQDtFPSma13sHO-C69tm_HTjHX5DnMX6B_lDCgu3A8AsSZIQEG71z_Mnd2uxHoUrKUtHr8iM9bhpPKMnaXx9jr0O1EtKAJDLkz4qdzNunyOU7Ud94Lc8YxIjf7FZH_-jJc0UqFyFKY2rdEiZQVATNG94F-SIWA4CK5FZtW47TCL8EPBUzP8gGG8g6eMBEIfv80uWQxpJ59_UB91D8U6zSOiA4JrFDBRLkIX2kGnUZ7eu1G-4O6TglL_Id0oMeJdNEsMARYKHGmYZjvHGFVoLyoxca1KDK5dlcnLsYyxfKsZWNrTaqA';
        $identityToken = IdentityToken::fromJwt($json);

        $this->assertSame('https://id.example.com', $identityToken->issuingAuthority);
        $this->assertSame('UWAYfzzmcaNAZy_C8a8UoUxMmhT1IlcKlXG8TnWkyIM', $identityToken->values['subject']);
    }
}
