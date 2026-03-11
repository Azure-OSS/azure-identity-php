<?php

namespace AzureOss\Identity;

class ManagedIdentityCredential implements TokenCredential
{

    public function __construct(private ManagedIdentityCredentialOptions $options = new ManagedIdentityCredentialOptions)
    {
    }

    public function getToken(TokenRequestContext $context): AccessToken
    {
        // TODO: Implement getToken() method.
    }
}