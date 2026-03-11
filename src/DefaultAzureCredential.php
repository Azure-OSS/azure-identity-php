<?php

declare(strict_types=1);

namespace AzureOss\Identity;

final class DefaultAzureCredential implements TokenCredential
{
    private TokenCredential $chain;

    public function __construct(
        private readonly DefaultAzureCredentialOptions $options = new DefaultAzureCredentialOptions
    ) {
        $this->chain = new ChainedTokenCredential([
            new EnvironmentCredential,
            new WorkloadIdentityCredential,
            new ManagedIdentityCredential,
        ]);
    }

    public function getToken(TokenRequestContext $context): AccessToken
    {
        return $this->chain->getToken($context);
    }
}
