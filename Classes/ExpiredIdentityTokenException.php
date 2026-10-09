<?php
declare(strict_types=1);
namespace Flownative\OpenIdConnect\Client;

/**
 * Thrown if an identity token passed all checks except its expiration time
 *
 * The validator checks the expiration time last, so a caller can still refresh such a token.
 */
final class ExpiredIdentityTokenException extends IdentityTokenRejectedException
{
}
