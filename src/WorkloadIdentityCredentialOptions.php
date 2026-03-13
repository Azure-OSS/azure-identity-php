<?php

declare(strict_types=1);

namespace AzureOss\Identity;

final class WorkloadIdentityCredentialOptions extends TokenCredentialOptions
{
    public function __construct(
        string $authorityHost = AzureAuthorityHosts::AZURE_PUBLIC_CLOUD,
        public readonly ?string $clientId = null,
        public readonly ?string $tenantId = null,
        public readonly ?string $tokenFilePath = null,
    ) {
        parent::__construct($authorityHost);
    }
}
