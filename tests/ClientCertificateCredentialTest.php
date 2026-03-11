<?php

declare(strict_types=1);

namespace AzureOss\Identity\Tests;

use AzureOss\Identity\AuthenticationFailedException;
use AzureOss\Identity\ClientCertificateCredential;
use AzureOss\Identity\TokenRequestContext;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

class ClientCertificateCredentialTest extends TestCase
{
    #[Test]
    public function get_token_works(): void
    {
        $tenantId = getenv('AZURE_TENANT_ID');
        $clientId = getenv('AZURE_CLIENT_ID');

        if ($tenantId === false || $clientId === false) {
            self::markTestSkipped('Not all env variables have been set for this test');
        }

        $clientCertificatePath = __DIR__.'/fixtures/test-cert.pem';

        $credential = new ClientCertificateCredential($tenantId, $clientId, $clientCertificatePath);
        $token = $credential->getToken(new TokenRequestContext(['https://graph.microsoft.com/.default']));

        self::assertGreaterThan(0, strlen($token->token));
        self::assertGreaterThan((new \DateTimeImmutable)->getTimestamp(), $token->expiresOn->getTimestamp());
        self::assertEquals('Bearer', $token->tokenType);
    }

    #[Test]
    public function get_token_throws_authentication_failed_exception_when_credentials_are_invalid(): void
    {
        $this->expectException(AuthenticationFailedException::class);

        (new ClientCertificateCredential('invalid', 'invalid', '/nonexistent/path.pem'))
            ->getToken(new TokenRequestContext(['https://graph.microsoft.com/.default']));
    }
}
