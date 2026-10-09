<?php
declare(strict_types=1);
namespace Flownative\OpenIdConnect\Client;

use Exception;

/**
 * Thrown if an identity token fails a check of the IdentityTokenValidator. The message says why, in a form which is safe to log.
 */
class IdentityTokenRejectedException extends Exception
{
}
