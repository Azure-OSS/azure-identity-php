<?php

declare(strict_types=1);

namespace AzureOss\Identity;

final class DefaultAzureCredentialOptions extends TokenCredentialOptions
{
    public function __construct(
        string $authorityHost = AzureAuthorityHosts::AZURE_PUBLIC_CLOUD,
        public readonly bool $excludeEnvironmentCredential = false,
        public readonly bool $excludeWorkloadIdentityCredential = false,
        public readonly bool $excludeManagedIdentityCredential = true,
        public readonly bool $excludeAzureCliCredential = false,
        public readonly bool $excludeAzureDeveloperCliCredential = false,
        public readonly bool $excludeAzurePowerShellCredential = false,
        public readonly bool $excludeInteractiveBrowserCredential = true,
        public readonly bool $excludeVisualStudioCredential = false,
        public readonly bool $excludeVisualStudioCodeCredential = false,
        public readonly bool $excludeBrokerCredential = false,
    ) {
        parent::__construct($authorityHost);
    }
}
