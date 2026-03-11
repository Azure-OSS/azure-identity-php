<?php

declare(strict_types=1);

namespace AzureOss\Identity;

class TokenCredentialOptions
{
    public function __construct(
        public readonly string $authorityHost = AzureAuthorityHosts::AZURE_PUBLIC_CLOUD,
    ) {}
}
