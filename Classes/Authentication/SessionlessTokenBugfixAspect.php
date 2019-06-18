<?php
declare(strict_types = 1);
namespace Flownative\OpenIdConnect\Client\Authentication;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Aop\JoinPointInterface;
use Neos\Flow\Security\Authentication\Token\SessionlessTokenInterface;

/**
 * An aspect which fixes a bug in SessionDataContainer:
 *
 * Without the fix, all security tokens – including those which are implementations of SessionlessTokenInterface –
 * are serialized and added to the current session. This is a problem for sessionless tokens, which need to be
 * updated on every request on not just once per session.
 *
 * @Flow\Aspect()
 */
class SessionlessTokenBugfixAspect
{
    /**
     * @param JoinPointInterface $joinPoint
     * @Flow\Before("method(Neos\Flow\Security\SessionDataContainer->setSecurityTokens(.*))")
     */
    public function setSecurityTokensAdvice(JoinPointInterface $joinPoint): void
    {
        $setterArgumentName = array_keys($joinPoint->getMethodArguments())[0];
        $securityTokens = $joinPoint->getMethodArgument($setterArgumentName);

        if (!is_array($securityTokens)) {
            throw new \RuntimeException(sprintf('%s: setter argument is not an array as expected.', __CLASS__), 1560781264);
        }

        $joinPoint->setMethodArgument($setterArgumentName,
            array_filter(
                $securityTokens,
                function ($token) {
                    return (!$token instanceof SessionlessTokenInterface);
                }
            )
        );
    }
}
