<?php

namespace AzureOss\Identity;

class WorkloadIdentityCredential implements TokenCredential
{
    public function __construct(private WorkloadIdentityCredentialOptions $options = new WorkloadIdentityCredentialOptions)
    {
    }

    public function getToken(TokenRequestContext $context): AccessToken
    {
        // TODO: Implement getToken() method.
    }
}