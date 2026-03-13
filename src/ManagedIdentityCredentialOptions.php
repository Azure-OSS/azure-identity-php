<?php

declare(strict_types=1);

namespace AzureOss\Identity;

final class ManagedIdentityCredentialOptions extends TokenCredentialOptions
{
    public function __construct(
        string $authorityHost = AzureAuthorityHosts::AZURE_PUBLIC_CLOUD,
        public readonly ?string $clientId = null,
    ) {
        parent::__construct($authorityHost);
    }
}
