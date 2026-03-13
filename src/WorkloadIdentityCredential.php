<?php

declare(strict_types=1);

namespace AzureOss\Identity;

use GuzzleHttp\Client;
use GuzzleHttp\RequestOptions;

final class WorkloadIdentityCredential implements TokenCredential
{
    public function __construct(
        private WorkloadIdentityCredentialOptions $options = new WorkloadIdentityCredentialOptions,
    ) {}

    public function getToken(TokenRequestContext $context): AccessToken
    {
        $tenantId = $this->options->tenantId ?? getenv('AZURE_TENANT_ID');
        $clientId = $this->options->clientId ?? getenv('AZURE_CLIENT_ID');
        $tokenFilePath = $this->options->tokenFilePath ?? getenv('AZURE_FEDERATED_TOKEN_FILE');

        if (! is_string($tenantId) || ! is_string($clientId) || ! is_string($tokenFilePath)) {
            throw new CredentialUnavailableException(
                'WorkloadIdentityCredential authentication unavailable. '
                .'The workload options are not fully configured. '
                .'Ensure tenantId, clientId, and tokenFilePath are provided via options or the '
                .'AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_FEDERATED_TOKEN_FILE environment variables.',
            );
        }

        try {
            $assertion = $this->readFederatedToken($tokenFilePath);

            $response = (new Client)->post("https://{$this->options->authorityHost}/{$tenantId}/oauth2/v2.0/token", [
                RequestOptions::HEADERS => [
                    'Content-Type' => 'application/x-www-form-urlencoded',
                ],
                RequestOptions::FORM_PARAMS => [
                    'grant_type' => 'client_credentials',
                    'client_id' => $clientId,
                    'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                    'client_assertion' => $assertion,
                    'scope' => implode(' ', $context->scopes),
                ],
            ]);

            return AccessToken::fromTokenResponse($response->getBody()->getContents());
        } catch (AuthenticationFailedException $e) {
            throw $e;
        } catch (\Throwable $e) {
            throw new AuthenticationFailedException('Failed to authenticate with Azure using workload identity', previous: $e);
        }
    }

    private function readFederatedToken(string $tokenFilePath): string
    {
        $token = file_get_contents($tokenFilePath);
        if ($token === false) {
            throw new AuthenticationFailedException("Unable to read federated token file: {$tokenFilePath}");
        }

        $token = trim($token);
        if ($token === '') {
            throw new AuthenticationFailedException("Federated token file is empty: {$tokenFilePath}");
        }

        return $token;
    }
}
