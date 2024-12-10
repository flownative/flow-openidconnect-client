<?php
declare(strict_types = 1);
namespace Flownative\OpenIdConnect\Client\Authentication;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Security\Cryptography\HashService;
use Neos\Flow\Security\Exception\InvalidHashException;
use Psr\Log\LoggerInterface;

final class TokenArguments implements \ArrayAccess
{
    public const AUTHORIZATION_ID = 'id';
    public const SERVICE_NAME = 'service';

    /**
     * @Flow\Inject
     * @var HashService
     */
    protected $hashService;

    /**
     * @Flow\Inject
     * @var LoggerInterface
     */
    protected $logger;

    /**
     * @var array
     */
    private $payload = [];

    /**
     * @param string $encodedString
     * @return TokenArguments
     * @throws \InvalidArgumentException
     */
    public static function fromSignedString(string $encodedString): TokenArguments
    {
        $returnArguments = new static();

        try {
            $payloadAsString = $returnArguments->hashService->validateAndStripHmac(base64_decode($encodedString));
            $returnArguments->payload = json_decode($payloadAsString, true);
        } catch (InvalidHashException) {
            throw new \InvalidArgumentException('OpenID Connect: The token arguments were appended by an invalid HMAC', 1560165515);
        }

        if (!is_array($returnArguments->payload)) {
            throw new \InvalidArgumentException('OpenID Connect: Failed decoding token arguments payload from given string', 1560162452);
        }
        return $returnArguments;
    }

    /**
     * @param array $array
     * @return TokenArguments
     * @throws \InvalidArgumentException
     */
    public static function fromArray(array $array): TokenArguments
    {
        $tokenArguments = new static();
        foreach ($array as $key => $value) {
            $tokenArguments[$key] = $value;
        }
        return $tokenArguments;
    }

    /**
     * @param mixed $offset
     * @return bool
     */
    public function offsetExists($offset): bool
    {
        return isset($this->payload[$offset]);
    }

    /**
     * @param mixed $offset
     * @return mixed
     */
    public function offsetGet($offset): mixed
    {
        return $this->payload[$offset] ?? null;
    }

    /**
     * @param mixed $offset
     * @param mixed $value
     */
    public function offsetSet($offset, $value): void
    {
        $this->payload[$offset] = match ($offset) {
            self::AUTHORIZATION_ID, self::SERVICE_NAME => $value,
            default => throw new \InvalidArgumentException(sprintf('OpenID Connect: Invalid argument name "%s" for token arguments', $offset), 1560162220),
        };
    }

    /**
     * @param mixed $offset
     */
    public function offsetUnset($offset): void
    {
        unset($this->payload[$offset]);
    }

    /**
     * @return string
     */
    public function __toString(): string
    {
        $json = json_encode($this->payload);
        try {
            $hmac = $this->hashService->generateHmac($json);
        } catch (\Throwable $throwable) {
            return 'ERROR: ' . $throwable->getMessage();
        }
        return base64_encode($json . $hmac);
    }
}
