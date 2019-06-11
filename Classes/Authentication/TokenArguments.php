<?php
declare(strict_types = 1);
namespace Flownative\OpenIdConnect\Client\Authentication;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Security\Cryptography\HashService;
use Neos\Flow\Security\Exception\InvalidArgumentForHashGenerationException;
use Neos\Flow\Security\Exception\InvalidHashException;

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
        } catch (InvalidHashException $exception) {
            throw new \InvalidArgumentException(sprintf('OpenID Connect: The token arguments were appended by an invalid HMAC'), 1560165515);
        }

        if (!is_array($returnArguments->payload)) {
            throw new \InvalidArgumentException(sprintf('OpenID Connect: Failed decoding token arguments payload from given string'), 1560162452);
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
    public function offsetGet($offset)
    {
        if (isset($this->payload[$offset])) {
            return $this->payload[$offset];
        }
    }

    /**
     * @param mixed $offset
     * @param mixed $value
     */
    public function offsetSet($offset, $value): void
    {
        switch($offset) {
            case self::AUTHORIZATION_ID:
            case self::SERVICE_NAME:
                $this->payload[$offset] = $value;
            break;
            default:
                throw new \InvalidArgumentException(sprintf('OpenID Connect: Invalid argument name "%s" for token arguments', $offset), 1560162220);
        }
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
     * @throws InvalidArgumentForHashGenerationException
     */
    public function __toString(): string
    {
        $json = json_encode($this->payload);
        $hmac = $this->hashService->generateHmac($json);
        return base64_encode($json . $hmac);
    }
}
