<?php

declare(strict_types=1);

namespace AzureOss\Identity;

final class WorkloadIdentityCredential implements TokenCredential
{
    public function __construct(
        /** @phpstan-ignore-next-line */
        private WorkloadIdentityCredentialOptions $options = new WorkloadIdentityCredentialOptions
    ) {}

    public function getToken(TokenRequestContext $context): AccessToken
    {
        throw new \Exception('Not implemented');
    }
}
