<?php

declare(strict_types=1);

namespace AzureOss\Identity;

final class ManagedIdentityCredential implements TokenCredential
{
    public function __construct(
        /** @phpstan-ignore-next-line */
        private ManagedIdentityCredentialOptions $options = new ManagedIdentityCredentialOptions
    ) {}

    public function getToken(TokenRequestContext $context): AccessToken
    {
        throw new \Exception('Not implemented');
    }
}
