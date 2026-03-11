<?php

declare(strict_types=1);

namespace AzureOss\Identity;

final class EnvironmentCredentialOptions
{
    public function __construct(
        public readonly string $authorityHost = AzureAuthorityHosts::AZURE_PUBLIC_CLOUD,
    ) {}
}
