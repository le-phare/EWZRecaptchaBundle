<?php declare(strict_types=1);

namespace EWZ\Tests\Bundle\RecaptchaBundle\Validator\Constraints;

use EWZ\Bundle\RecaptchaBundle\Validator\Constraints\IsTrue;
use EWZ\Bundle\RecaptchaBundle\Validator\Constraints\IsTrueV3;
use PHPUnit\Framework\TestCase;

class IsTrueTest extends TestCase
{
    public function testDefaults(): void
    {
        $constraint = new IsTrue();

        self::assertSame('This value is not a valid captcha.', $constraint->message);
        self::assertSame('The captcha was not resolved on the right domain.', $constraint->invalidHostMessage);
        self::assertSame(['Default'], $constraint->groups);
        self::assertNull($constraint->payload);
    }

    public function testArguments(): void
    {
        $constraint = new IsTrue(null, 'message', 'host message', ['registration'], 'payload');

        self::assertSame('message', $constraint->message);
        self::assertSame('host message', $constraint->invalidHostMessage);
        self::assertSame(['registration'], $constraint->groups);
        self::assertSame('payload', $constraint->payload);
    }

    public function testOptionsArray(): void
    {
        $constraint = @new IsTrueV3([
            'message' => 'message',
            'invalidHostMessage' => 'host message',
            'groups' => ['registration'],
            'payload' => 'payload',
        ]);

        self::assertSame('message', $constraint->message);
        self::assertSame('host message', $constraint->invalidHostMessage);
        self::assertSame(['registration'], $constraint->groups);
        self::assertSame('payload', $constraint->payload);
    }

    public function testNoDeprecationWithoutOptionsArray(): void
    {
        $deprecations = [];
        set_error_handler(static function (int $type, string $message) use (&$deprecations): bool {
            $deprecations[] = $message;

            return true;
        }, E_USER_DEPRECATED);

        try {
            new IsTrue();
            new IsTrueV3(null, 'message');
        } finally {
            restore_error_handler();
        }

        self::assertSame([], $deprecations);
    }
}
