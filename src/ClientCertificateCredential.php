<?php

declare(strict_types=1);

namespace AzureOss\Identity;

use GuzzleHttp\Client;
use GuzzleHttp\RequestOptions;

final class ClientCertificateCredential implements TokenCredential
{
    public function __construct(
        private readonly string $tenantId,
        private readonly string $clientId,
        private readonly string $clientCertificatePath,
        private readonly ClientCertificateCredentialOptions $options = new ClientCertificateCredentialOptions,
    ) {}

    public function getToken(TokenRequestContext $context): AccessToken
    {
        try {
            $assertion = $this->createClientAssertion();

            $response = (new Client)->post("https://{$this->options->authorityHost}/{$this->tenantId}/oauth2/v2.0/token", [
                RequestOptions::HEADERS => [
                    'Content-Type' => 'application/x-www-form-urlencoded',
                ],
                RequestOptions::FORM_PARAMS => [
                    'grant_type' => 'client_credentials',
                    'client_id' => $this->clientId,
                    'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                    'client_assertion' => $assertion,
                    'scope' => implode(' ', $context->scopes),
                ],
            ]);

            return AccessToken::fromTokenResponse($response->getBody()->getContents());
        } catch (AuthenticationFailedException $e) {
            throw $e;
        } catch (\Throwable $e) {
            throw new AuthenticationFailedException('Failed to authenticate with Azure', previous: $e);
        }
    }

    private function createClientAssertion(): string
    {
        $pemContents = file_get_contents($this->clientCertificatePath);

        if ($pemContents === false) {
            throw new \RuntimeException("Unable to read certificate file: {$this->clientCertificatePath}");
        }

        // Extract the certificate
        $certificate = openssl_x509_read($pemContents);
        if ($certificate === false) {
            throw new \RuntimeException('Unable to parse the certificate from the PEM file');
        }

        // Extract the private key
        $privateKey = openssl_pkey_get_private($pemContents);
        if ($privateKey === false) {
            throw new \RuntimeException('Unable to extract private key from the PEM file');
        }

        // Compute the x5t (X.509 certificate SHA-1 thumbprint)
        $thumbprint = $this->getCertificateThumbprint($certificate);

        // Build the JWT header
        $header = [
            'alg' => 'RS256',
            'typ' => 'JWT',
            'x5t' => $thumbprint,
        ];

        $tokenEndpoint = "https://{$this->options->authorityHost}/{$this->tenantId}/oauth2/v2.0/token";
        $now = time();

        // Build the JWT payload
        $payload = [
            'aud' => $tokenEndpoint,
            'iss' => $this->clientId,
            'sub' => $this->clientId,
            'jti' => bin2hex(random_bytes(16)),
            'nbf' => $now,
            'iat' => $now,
            'exp' => $now + 600,
        ];

        // Encode header and payload
        $headerJson = json_encode($header, JSON_THROW_ON_ERROR);
        $payloadJson = json_encode($payload, JSON_THROW_ON_ERROR);

        $encodedHeader = $this->base64UrlEncode($headerJson);
        $encodedPayload = $this->base64UrlEncode($payloadJson);

        $dataToSign = "{$encodedHeader}.{$encodedPayload}";

        // Sign with the private key
        $signature = '';
        if (! openssl_sign($dataToSign, $signature, $privateKey, OPENSSL_ALGO_SHA256)) {
            throw new \RuntimeException('Failed to sign the JWT assertion');
        }

        $encodedSignature = $this->base64UrlEncode($signature);

        return "{$dataToSign}.{$encodedSignature}";
    }

    private function getCertificateThumbprint(\OpenSSLCertificate $certificate): string
    {
        $pemString = '';
        if (! openssl_x509_export($certificate, $pemString)) {
            throw new \RuntimeException('Unable to export certificate');
        }

        // Remove PEM armor to get raw DER bytes
        $stripped = preg_replace('/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s/', '', $pemString);
        if (! is_string($stripped)) {
            throw new \RuntimeException('Failed to strip PEM headers');
        }

        $derBytes = base64_decode($stripped, true);
        if ($derBytes === false) {
            throw new \RuntimeException('Failed to decode certificate DER data');
        }

        // SHA-1 thumbprint, base64url-encoded (this is the x5t format)
        return $this->base64UrlEncode(hash('sha1', $derBytes, true));
    }

    private function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
}
