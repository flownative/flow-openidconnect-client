<?php
declare(strict_types=1);
namespace Flownative\OpenIdConnect\Client\Authentication;

use ArrayAccess;
use InvalidArgumentException;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Security\Cryptography\HashService;
use Neos\Flow\Security\Exception\InvalidHashException;
use Throwable;

/**
 * Arguments which are passed through the authorization redirect, protected by an HMAC
 */
#[Flow\Proxy(false)]
final class TokenArguments implements ArrayAccess
{
    public const string AUTHORIZATION_ID = 'id';
    public const string SERVICE_NAME = 'service';

    private array $payload = [];

    private function __construct(
        private readonly HashService $hashService
    ) {
    }

    /**
     * @throws InvalidArgumentException
     */
    public static function fromSignedString(string $encodedString, HashService $hashService): self
    {
        try {
            $payloadAsString = $hashService->validateAndStripHmac(base64_decode($encodedString));
            $payload = json_decode($payloadAsString, true);
        } catch (InvalidHashException) {
            throw new InvalidArgumentException('OpenID Connect: The token arguments were appended by an invalid HMAC', 1560165515);
        }

        if (!is_array($payload)) {
            throw new InvalidArgumentException('OpenID Connect: Failed decoding token arguments payload from given string', 1560162452);
        }
        $returnArguments = new self($hashService);
        $returnArguments->payload = $payload;
        return $returnArguments;
    }

    /**
     * @throws InvalidArgumentException
     */
    public static function fromArray(array $array, HashService $hashService): self
    {
        $tokenArguments = new self($hashService);
        foreach ($array as $key => $value) {
            $tokenArguments[$key] = $value;
        }
        return $tokenArguments;
    }

    public function offsetExists(mixed $offset): bool
    {
        return isset($this->payload[$offset]);
    }

    public function offsetGet(mixed $offset): mixed
    {
        return $this->payload[$offset] ?? null;
    }

    public function offsetSet(mixed $offset, mixed $value): void
    {
        $this->payload[$offset] = match ($offset) {
            self::AUTHORIZATION_ID, self::SERVICE_NAME => $value,
            default => throw new InvalidArgumentException(sprintf('OpenID Connect: Invalid argument name "%s" for token arguments', $offset), 1560162220),
        };
    }

    public function offsetUnset(mixed $offset): void
    {
        unset($this->payload[$offset]);
    }

    public function __toString(): string
    {
        $json = json_encode($this->payload);
        try {
            $hmac = $this->hashService->generateHmac($json);
        } catch (Throwable $throwable) {
            return 'ERROR: ' . $throwable->getMessage();
        }
        return base64_encode($json . $hmac);
    }
}
