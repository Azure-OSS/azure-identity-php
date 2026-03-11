<?php

declare(strict_types=1);

namespace AzureOss\Identity;

final class ClientCertificateCredentialOptions extends TokenCredentialOptions
{
    public function __construct(
        string $authorityHost = AzureAuthorityHosts::AZURE_PUBLIC_CLOUD,
        public readonly bool $sendCertificateChain = false,
    ) {
        parent::__construct($authorityHost);
    }
}
