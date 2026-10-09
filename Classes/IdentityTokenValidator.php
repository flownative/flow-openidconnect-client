<?php
declare(strict_types=1);
namespace Flownative\OpenIdConnect\Client;

use DateInterval;
use DateTimeImmutable;
use Neos\Flow\Annotations as Flow;

/**
 * Decides if an identity token can be trusted: signature, issuer, audience, authorized party, time, nonce and account identifier
 *
 * The OpenIdConnectProvider validates every token with it, and applications which obtain identity tokens in another way can do the same.
 *
 * @see https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
 */
#[Flow\Scope('singleton')]
final class IdentityTokenValidator
{
    /**
     * The expiration time is checked last, so that an ExpiredIdentityTokenException means that all other checks passed
     *
     * @param array $jwks The JSON Web Key Set of the identity provider, see OpenIdConnectClient::getJwks()
     * @throws ExpiredIdentityTokenException
     * @throws IdentityTokenRejectedException
     */
    public function validate(IdentityToken $identityToken, array $jwks, IdentityTokenRequirements $requirements, ?DateTimeImmutable $now = null): ValidatedIdentityToken
    {
        $now ??= new DateTimeImmutable();
        $leewayInterval = new DateInterval('PT' . $requirements->leeway . 'S');

        try {
            $hasValidSignature = $identityToken->hasValidSignature($jwks);
        } catch (ServiceException $exception) {
            throw new IdentityTokenRejectedException(sprintf('its signature could not be verified: %s', $exception->getMessage()), 1791540860, $exception);
        }
        if (!$hasValidSignature) {
            throw new IdentityTokenRejectedException('its signature is invalid', 1791540861);
        }

        $issuerMatches = false;
        foreach (self::resolveIssuers($requirements->issuers, $identityToken) as $expectedIssuer) {
            if ($identityToken->isIssuedBy($expectedIssuer)) {
                $issuerMatches = true;
                break;
            }
        }
        if (!$issuerMatches) {
            throw new IdentityTokenRejectedException(sprintf('its issuer %s does not match the expected issuer', self::describeValue($identityToken->values['iss'] ?? null)), 1791540862);
        }

        $audienceMatches = false;
        foreach ($requirements->audiences as $expectedAudience) {
            if ($identityToken->audienceContains($expectedAudience)) {
                $audienceMatches = true;
                break;
            }
        }
        if (!$audienceMatches) {
            throw new IdentityTokenRejectedException(sprintf('its audience %s contains none of %s', self::describeValue($identityToken->values['aud'] ?? null), self::describeValue($requirements->audiences)), 1791540863);
        }

        if ($requirements->authorizedParty !== null) {
            self::checkAuthorizedParty($identityToken, $requirements->authorizedParty);
        }

        if ($identityToken->isNotYetValidAt($now->add($leewayInterval))) {
            throw new IdentityTokenRejectedException('it is not valid yet', 1791540864);
        }

        if ($requirements->nonce !== null) {
            $nonce = $identityToken->values['nonce'] ?? null;
            if (!is_string($nonce) || !hash_equals($requirements->nonce, $nonce)) {
                throw new IdentityTokenRejectedException('its nonce is missing or not the expected one', 1791540865);
            }
        }

        $accountIdentifier = $identityToken->values[$requirements->accountIdentifierClaimName] ?? null;
        if (!is_string($accountIdentifier) || $accountIdentifier === '') {
            throw new IdentityTokenRejectedException(sprintf('its claim "%s", which is used as account identifier, is missing or not a string', $requirements->accountIdentifierClaimName), 1791540866);
        }
        // Identity providers may let users choose an email address without verifying it, so it only identifies an account once it is verified.
        if ($requirements->accountIdentifierClaimName === 'email' && $requirements->requireVerifiedEmail && !in_array($identityToken->values['email_verified'] ?? null, [true, 'true'], true)) {
            throw new IdentityTokenRejectedException('its email address, which is used as account identifier, is not verified', 1791540867);
        }

        if ($identityToken->isExpiredAt($now->sub($leewayInterval))) {
            throw new ExpiredIdentityTokenException('it is expired', 1791540868);
        }

        return new ValidatedIdentityToken($identityToken, $accountIdentifier);
    }

    /**
     * A token for several audiences must name the client it was issued to, and a token which names a client must name this one
     *
     * @see https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation, items 4 and 5
     */
    private static function checkAuthorizedParty(IdentityToken $identityToken, string $expectedAuthorizedParty): void
    {
        $audienceClaim = $identityToken->values['aud'] ?? null;
        $hasSeveralAudiences = is_array($audienceClaim) && count($audienceClaim) > 1;
        if (!array_key_exists('azp', $identityToken->values)) {
            if ($hasSeveralAudiences) {
                throw new IdentityTokenRejectedException('it has several audiences but no authorized party', 1791540869);
            }
            return;
        }
        if ($identityToken->values['azp'] !== $expectedAuthorizedParty) {
            throw new IdentityTokenRejectedException(sprintf('its authorized party %s is not %s', self::describeValue($identityToken->values['azp']), self::describeValue($expectedAuthorizedParty)), 1791540870);
        }
    }

    /**
     * Issuers containing "{tenantid}" are resolved with the "tid" claim of the token, and left out if the token has no valid "tid"
     *
     * @param string[] $issuers
     * @return string[]
     */
    private static function resolveIssuers(array $issuers, IdentityToken $identityToken): array
    {
        $tenantIdentifier = $identityToken->values['tid'] ?? null;
        $hasValidTenantIdentifier = is_string($tenantIdentifier) && preg_match('/^[a-zA-Z0-9-]+\z/', $tenantIdentifier) === 1;

        $resolvedIssuers = [];
        foreach ($issuers as $issuer) {
            if (!str_contains($issuer, '{tenantid}')) {
                $resolvedIssuers[] = $issuer;
            } elseif ($hasValidTenantIdentifier) {
                $resolvedIssuers[] = str_replace('{tenantid}', $tenantIdentifier, $issuer);
            }
        }
        return $resolvedIssuers;
    }

    /**
     * Returns a value taken from a token in a form which is safe to write into a log message
     */
    private static function describeValue(mixed $value): string
    {
        $description = json_encode($value, JSON_UNESCAPED_SLASHES | JSON_PARTIAL_OUTPUT_ON_ERROR);
        return mb_substr($description === false ? '?' : $description, 0, 200);
    }
}
