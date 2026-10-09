<?php
declare(strict_types=1);
namespace Flownative\OpenIdConnect\Client;

use InvalidArgumentException;
use Neos\Flow\Annotations as Flow;

/**
 * What an identity token must fulfil to be accepted by the IdentityTokenValidator
 *
 * The authorized party ("azp") is a required argument, so that every caller decides about it: the client id for identity tokens issued
 * to this client, or null for access tokens which other clients obtained for an API.
 *
 * @see https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
 */
#[Flow\Proxy(false)]
final readonly class IdentityTokenRequirements
{
    /**
     * @param string[] $issuers Of which one must have issued the token. The placeholder "{tenantid}" is replaced by the "tid" claim, as used by multi-tenant applications of Microsoft Entra ID
     * @param string[] $audiences Of which the "aud" claim must contain at least one
     * @param string|null $authorizedParty The client id which "azp" must name if present, and which must be present if the token has several audiences. Null if "azp" is not checked
     * @param string $accountIdentifierClaimName The claim which identifies the account. If it is "email", the address must be verified, unless $requireVerifiedEmail is false
     * @param int $leeway Seconds which compensate for clock differences between the identity provider and this application
     * @param string|null $nonce The nonce which the token must contain, or null if the caller checks it in another way
     */
    public function __construct(
        public array $issuers,
        public array $audiences,
        public ?string $authorizedParty,
        public string $accountIdentifierClaimName = 'sub',
        public bool $requireVerifiedEmail = true,
        public int $leeway = 60,
        public ?string $nonce = null,
    ) {
        if ($issuers === [] || !array_is_list($issuers) || array_filter($issuers, static fn (mixed $issuer): bool => !is_string($issuer) || $issuer === '') !== []) {
            throw new InvalidArgumentException('The expected issuers must be a non-empty list of non-empty strings', 1791540854);
        }
        if ($audiences === [] || !array_is_list($audiences) || array_filter($audiences, static fn (mixed $audience): bool => !is_string($audience) || $audience === '') !== []) {
            throw new InvalidArgumentException('The expected audiences must be a non-empty list of non-empty strings', 1791540855);
        }
        if ($authorizedParty === '') {
            throw new InvalidArgumentException('The expected authorized party must not be empty, use null to not check it', 1791540856);
        }
        if ($accountIdentifierClaimName === '') {
            throw new InvalidArgumentException('The name of the claim which identifies the account must not be empty', 1791540857);
        }
        if ($leeway < 0) {
            throw new InvalidArgumentException('The leeway must be zero or a positive number of seconds', 1791540858);
        }
        if ($nonce === '') {
            throw new InvalidArgumentException('The expected nonce must not be empty, use null to not check it', 1791540859);
        }
    }
}
