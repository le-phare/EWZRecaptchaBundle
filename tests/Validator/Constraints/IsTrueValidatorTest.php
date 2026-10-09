<?php declare(strict_types=1);

namespace EWZ\Tests\Bundle\RecaptchaBundle\Validator\Constraints;

use EWZ\Bundle\RecaptchaBundle\Validator\Constraints\IsTrue;
use EWZ\Bundle\RecaptchaBundle\Validator\Constraints\IsTrueValidator;
use PHPUnit\Framework\TestCase;
use ReCaptcha\ReCaptcha;
use ReCaptcha\Response;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;
use Symfony\Component\Validator\Context\ExecutionContextInterface;

class IsTrueValidatorTest extends TestCase
{

    public function testNotEnabled(): void
    {
        $reCaptcha = $this->createMock(ReCaptcha::class);
        $reCaptcha->expects(self::never())
            ->method('verify');
        $requestStack = $this->createMock(RequestStack::class);
        $authorizationChecker = $this->createMock(AuthorizationCheckerInterface::class);
        $context = $this->createMock(ExecutionContextInterface::class);
        $context->expects(self::never())
            ->method('addViolation');
        $context->expects(self::never())
            ->method('buildViolation');

        $authorizationChecker->expects(self::never())
            ->method('isGranted');

        $validator = new IsTrueValidator(false, $reCaptcha, $requestStack, true, $authorizationChecker, []);
        $validator->initialize($context);
        $validator->validate('', new IsTrue());
    }

    public function testTrustedRolesAreNotValidated(): void
    {
        $trustedRoles = ['ROLE_TEST'];
        $reCaptcha = $this->createMock(ReCaptcha::class);
        $reCaptcha->expects(self::never())
            ->method('verify');
        $requestStack = $this->createMock(RequestStack::class);
        $authorizationChecker = $this->createMock(AuthorizationCheckerInterface::class);
        $context = $this->createMock(ExecutionContextInterface::class);
        $context->expects(self::never())
            ->method('addViolation');
        $context->expects(self::never())
            ->method('buildViolation');

        $authorizationChecker->expects(self::once())
            ->method('isGranted')
            ->with('ROLE_TEST')
            ->willReturn(true);

        if (\is_callable([$requestStack, 'getMainRequest'])) {
            $requestStack->expects(self::never())
                ->method('getMainRequest');
        } else {
            $requestStack->expects(self::never())
                ->method('getMasterRequest');
        }

        $validator = new IsTrueValidator(true, $reCaptcha, $requestStack, true, $authorizationChecker, $trustedRoles);
        $validator->validate('', new IsTrue());
    }

    public function testAnyTrustedRoleIsNotValidated(): void
    {
        $reCaptcha = $this->createMock(ReCaptcha::class);
        $reCaptcha->expects(self::never())
            ->method('verify');
        $requestStack = $this->createMock(RequestStack::class);
        $authorizationChecker = $this->createMock(AuthorizationCheckerInterface::class);
        $context = $this->createMock(ExecutionContextInterface::class);
        $context->expects(self::never())
            ->method('addViolation');

        $authorizationChecker->expects(self::exactly(2))
            ->method('isGranted')
            ->willReturnCallback(function ($role) {
                return 'ROLE_B' === $role;
            });

        $validator = new IsTrueValidator(true, $reCaptcha, $requestStack, true, $authorizationChecker, ['ROLE_A', 'ROLE_B']);
        $validator->initialize($context);
        $validator->validate('', new IsTrue());
    }

    public function testResponseNotSuccess(): void
    {
        $trustedRoles = ['ROLE_TEST'];
        $clientIp = '127.0.0.1';
        $recaptchaAnswer = 'encoded response';
        $constraint = new IsTrue();
        $reCaptcha = $this->createMock(ReCaptcha::class);
        $requestStack = $this->createMock(RequestStack::class);
        $authorizationChecker = $this->createMock(AuthorizationCheckerInterface::class);
        $context = $this->createMock(ExecutionContextInterface::class);
        $context->expects(self::never())
            ->method('buildViolation');

        $authorizationChecker->expects(self::once())
            ->method('isGranted')
            ->with('ROLE_TEST')
            ->willReturn(false);

        $request = new Request([], ['g-recaptcha-response' => $recaptchaAnswer], [], [], [], ['REMOTE_ADDR' => $clientIp]);

        if (\is_callable([$requestStack, 'getMainRequest'])) {
            $requestStack->expects(self::once())
                ->method('getMainRequest')
                ->willReturn($request);
        } else {
            $requestStack->expects(self::once())
                ->method('getMasterRequest')
                ->willReturn($request);
        }

        $response = new Response(false);

        $reCaptcha->expects(self::once())
            ->method('verify')
            ->with($recaptchaAnswer, $clientIp)
            ->willReturn($response);

        $context->expects(self::once())
            ->method('addViolation')
            ->with($constraint->message);

        $validator = new IsTrueValidator(true, $reCaptcha, $requestStack, true, $authorizationChecker, $trustedRoles);
        $validator->initialize($context);
        $validator->validate('', $constraint);
    }

    public function testInvalidHostWithVerifyHost(): void
    {
        $trustedRoles = ['ROLE_TEST'];
        $clientIp = '127.0.0.1';
        $recaptchaAnswer = 'encoded response';
        $constraint = new IsTrue();
        $reCaptcha = $this->createMock(ReCaptcha::class);
        $requestStack = $this->createMock(RequestStack::class);
        $authorizationChecker = $this->createMock(AuthorizationCheckerInterface::class);
        $context = $this->createMock(ExecutionContextInterface::class);
        $context->expects(self::never())
            ->method('buildViolation');

        $authorizationChecker->expects(self::once())
            ->method('isGranted')
            ->with('ROLE_TEST')
            ->willReturn(false);

        $request = new Request([], ['g-recaptcha-response' => $recaptchaAnswer], [], [], [], ['REMOTE_ADDR' => $clientIp, 'HTTP_HOST' => 'host1']);

        if (\is_callable([$requestStack, 'getMainRequest'])) {
            $requestStack->expects(self::once())
                ->method('getMainRequest')
                ->willReturn($request);
        } else {
            $requestStack->expects(self::once())
                ->method('getMasterRequest')
                ->willReturn($request);
        }

        $response = new Response(true, [], 'host2');

        $reCaptcha->expects(self::once())
            ->method('verify')
            ->with($recaptchaAnswer, $clientIp)
            ->willReturn($response);

        $context->expects(self::once())
            ->method('addViolation')
            ->with($constraint->invalidHostMessage);

        $validator = new IsTrueValidator(true, $reCaptcha, $requestStack, true, $authorizationChecker, $trustedRoles);
        $validator->initialize($context);
        $validator->validate('', $constraint);
    }

    public function testInvalidHostWithoutVerifyHost(): void
    {
        $trustedRoles = ['ROLE_TEST'];
        $clientIp = '127.0.0.1';
        $recaptchaAnswer = 'encoded response';
        $constraint = new IsTrue();
        $reCaptcha = $this->createMock(ReCaptcha::class);
        $requestStack = $this->createMock(RequestStack::class);
        $authorizationChecker = $this->createMock(AuthorizationCheckerInterface::class);
        $context = $this->createMock(ExecutionContextInterface::class);
        $context->expects(self::never())
            ->method('buildViolation');

        $authorizationChecker->expects(self::once())
            ->method('isGranted')
            ->with('ROLE_TEST')
            ->willReturn(false);

        $request = new Request([], ['g-recaptcha-response' => $recaptchaAnswer], [], [], [], ['REMOTE_ADDR' => $clientIp]);

        if (\is_callable([$requestStack, 'getMainRequest'])) {
            $requestStack->expects(self::once())
                ->method('getMainRequest')
                ->willReturn($request);
        } else {
            $requestStack->expects(self::once())
                ->method('getMasterRequest')
                ->willReturn($request);
        }

        $response = new Response(true);

        $reCaptcha->expects(self::once())
            ->method('verify')
            ->with($recaptchaAnswer, $clientIp)
            ->willReturn($response);

        $context->expects(self::never())
            ->method('addViolation');

        $validator = new IsTrueValidator(true, $reCaptcha, $requestStack, false, $authorizationChecker, $trustedRoles);
        $validator->initialize($context);
        $validator->validate('', $constraint);
    }

    public function testValidWithVerifyHost(): void
    {
        $trustedRoles = ['ROLE_TEST'];
        $clientIp = '127.0.0.1';
        $recaptchaAnswer = 'encoded response';
        $host = 'host';
        $constraint = new IsTrue();
        $reCaptcha = $this->createMock(ReCaptcha::class);
        $requestStack = $this->createMock(RequestStack::class);
        $authorizationChecker = $this->createMock(AuthorizationCheckerInterface::class);
        $context = $this->createMock(ExecutionContextInterface::class);
        $context->expects(self::never())
            ->method('buildViolation');
        $context->expects(self::never())
            ->method('addViolation');

        $authorizationChecker->expects(self::once())
            ->method('isGranted')
            ->with('ROLE_TEST')
            ->willReturn(false);

        $request = new Request([], ['g-recaptcha-response' => $recaptchaAnswer], [], [], [], ['REMOTE_ADDR' => $clientIp, 'HTTP_HOST' => $host]);

        if (\is_callable([$requestStack, 'getMainRequest'])) {
            $requestStack->expects(self::once())
                ->method('getMainRequest')
                ->willReturn($request);
        } else {
            $requestStack->expects(self::once())
                ->method('getMasterRequest')
                ->willReturn($request);
        }

        $response = new Response(true, [], $host);

        $reCaptcha->expects(self::once())
            ->method('verify')
            ->with($recaptchaAnswer, $clientIp)
            ->willReturn($response);

        $validator = new IsTrueValidator(true, $reCaptcha, $requestStack, true, $authorizationChecker, $trustedRoles);
        $validator->initialize($context);
        $validator->validate('', $constraint);
    }

    public function testAnswerIsReadFromQueryString(): void
    {
        $clientIp = '127.0.0.1';
        $recaptchaAnswer = 'encoded response';
        $reCaptcha = $this->createMock(ReCaptcha::class);
        $requestStack = $this->createMock(RequestStack::class);
        $context = $this->createMock(ExecutionContextInterface::class);
        $context->expects(self::never())
            ->method('addViolation');

        $request = new Request(['g-recaptcha-response' => $recaptchaAnswer], [], [], [], [], ['REMOTE_ADDR' => $clientIp]);

        if (\is_callable([$requestStack, 'getMainRequest'])) {
            $requestStack->method('getMainRequest')->willReturn($request);
        } else {
            $requestStack->method('getMasterRequest')->willReturn($request);
        }

        $reCaptcha->expects(self::once())
            ->method('verify')
            ->with($recaptchaAnswer, $clientIp)
            ->willReturn(new Response(true));

        $validator = new IsTrueValidator(true, $reCaptcha, $requestStack, false);
        $validator->initialize($context);
        $validator->validate('', new IsTrue());
    }

}
