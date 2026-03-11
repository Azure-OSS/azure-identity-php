<?php

declare(strict_types=1);

namespace AzureOss\Identity;

use GuzzleHttp\Client;
use GuzzleHttp\RequestOptions;

final class ClientSecretCredential implements TokenCredential
{
    public function __construct(
        private readonly string $tenantId,
        private readonly string $clientId,
        private readonly string $clientSecret,
        private readonly TokenCredentialOptions $options = new TokenCredentialOptions,
    ) {}

    public function getToken(TokenRequestContext $context): AccessToken
    {
        try {
            $response = (new Client)->post("https://{$this->options->authorityHost}/{$this->tenantId}/oauth2/v2.0/token", [
                RequestOptions::HEADERS => [
                    'Content-Type' => 'application/x-www-form-urlencoded',
                ],
                RequestOptions::FORM_PARAMS => [
                    'grant_type' => 'client_credentials',
                    'client_id' => $this->clientId,
                    'client_secret' => $this->clientSecret,
                    'scope' => implode(' ', $context->scopes),
                ],
            ]);

            return AccessToken::fromTokenResponse($response->getBody()->getContents());
        } catch (\Throwable $e) {
            throw new AuthenticationFailedException('Failed to authenticate with Azure', previous: $e);
        }
    }
}
