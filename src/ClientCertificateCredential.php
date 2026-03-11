<?php

declare(strict_types=1);

namespace AzureOss\Identity;

use Firebase\JWT\JWT;
use GuzzleHttp\Client;
use GuzzleHttp\RequestOptions;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA\PrivateKey as RsaPrivateKey;
use phpseclib3\File\X509;

final class ClientCertificateCredential implements TokenCredential
{
    public function __construct(
        private readonly string $tenantId,
        private readonly string $clientId,
        private readonly string $clientCertificatePath,
        private readonly ?string $clientCertificatePassword = null,
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
        $material = $this->loadCertificateMaterial();

        $thumbprint = JWT::urlsafeB64Encode(
            hash('sha256', $material['leafCertificateDer'], true),
        );

        $header = [
            'typ' => 'JWT',
            'x5t#S256' => $thumbprint,
        ];

        if ($this->options->sendCertificateChain) {
            $header['x5c'] = array_map(
                fn (string $der): string => base64_encode($der),
                $material['certificateChainDer'],
            );
        }

        $tokenEndpoint = "https://{$this->options->authorityHost}/{$this->tenantId}/oauth2/v2.0/token";
        $now = time();

        $payload = [
            'aud' => $tokenEndpoint,
            'iss' => $this->clientId,
            'sub' => $this->clientId,
            'jti' => bin2hex(random_bytes(16)),
            'nbf' => $now,
            'iat' => $now,
            'exp' => $now + 600,
        ];

        $signingKey = $material['privateKey']->withPassword('');
        if (! $signingKey instanceof RsaPrivateKey) {
            throw new \RuntimeException('Unable to prepare private key for signing');
        }

        return JWT::encode(
            $payload,
            $signingKey->toString('PKCS8'),
            'RS256',
            null,
            $header,
        );
    }

    /**
     * @return array{
     *     privateKey: RsaPrivateKey,
     *     leafCertificateDer: string,
     *     certificateChainDer: list<string>
     * }
     */
    private function loadCertificateMaterial(): array
    {
        $contents = file_get_contents($this->clientCertificatePath);
        if ($contents === false) {
            throw new \RuntimeException("Unable to read certificate file: {$this->clientCertificatePath}");
        }

        if (preg_match('/-----BEGIN (CERTIFICATE|PRIVATE KEY|RSA PRIVATE KEY|ENCRYPTED PRIVATE KEY)-----/', $contents) === 1) {
            return $this->loadPemCertificateMaterial($contents);
        }

        return $this->loadPkcs12CertificateMaterial($contents);
    }

    /**
     * @return array{
     *     privateKey: RsaPrivateKey,
     *     leafCertificateDer: string,
     *     certificateChainDer: list<string>
     * }
     */
    private function loadPemCertificateMaterial(string $pemContents): array
    {
        $password = $this->clientCertificatePassword ?? '';

        $privateKey = PublicKeyLoader::load($pemContents, $password);
        if (! $privateKey instanceof RsaPrivateKey) {
            throw new \RuntimeException(
                'Unable to decrypt private key. The passphrase may be incorrect or the certificate file is invalid.',
            );
        }

        $certificateChainDer = $this->parseCertificateDerFromPem($pemContents);
        if ($certificateChainDer === []) {
            throw new \RuntimeException('Unable to parse the certificate from the PEM file');
        }

        return [
            'privateKey' => $privateKey,
            'leafCertificateDer' => $certificateChainDer[0],
            'certificateChainDer' => $certificateChainDer,
        ];
    }

    /**
     * @return array{
     *     privateKey: RsaPrivateKey,
     *     leafCertificateDer: string,
     *     certificateChainDer: list<string>
     * }
     */
    private function loadPkcs12CertificateMaterial(string $pkcs12Contents): array
    {
        $pkcs12DataRaw = [];
        if (! openssl_pkcs12_read($pkcs12Contents, $pkcs12DataRaw, $this->clientCertificatePassword ?? '')) {
            throw new \RuntimeException(
                'Unable to decrypt private key. The passphrase may be incorrect or the certificate file is invalid.',
            );
        }
        if (! is_array($pkcs12DataRaw)) {
            throw new \RuntimeException('Unable to parse the PKCS#12 file');
        }

        /** @var array<string, mixed> $pkcs12Data */
        $pkcs12Data = $pkcs12DataRaw;

        $leafCertPem = $pkcs12Data['cert'] ?? null;
        if (! is_string($leafCertPem)) {
            throw new \RuntimeException('Unable to parse the certificate from the PKCS#12 file');
        }

        $privateKeyPem = $pkcs12Data['pkey'] ?? null;
        if (! is_string($privateKeyPem)) {
            throw new \RuntimeException(
                'Unable to decrypt private key. The passphrase may be incorrect or the certificate file is invalid.',
            );
        }

        $privateKey = PublicKeyLoader::load($privateKeyPem);
        if (! $privateKey instanceof RsaPrivateKey) {
            throw new \RuntimeException('Unable to load private key from PKCS#12 file');
        }

        $certificateChainDer = $this->parseCertificateDerFromPem($leafCertPem);

        $extraCerts = $pkcs12Data['extracerts'] ?? null;
        if (is_array($extraCerts)) {
            foreach ($extraCerts as $extraCertPem) {
                if (is_string($extraCertPem)) {
                    $certificateChainDer = array_merge(
                        $certificateChainDer,
                        $this->parseCertificateDerFromPem($extraCertPem),
                    );
                }
            }
        }

        if ($certificateChainDer === []) {
            throw new \RuntimeException('Unable to parse the certificate from the PKCS#12 file');
        }

        return [
            'privateKey' => $privateKey,
            'leafCertificateDer' => $certificateChainDer[0],
            'certificateChainDer' => $certificateChainDer,
        ];
    }

    /**
     * Parse PEM content and return DER-encoded bytes for each certificate found.
     *
     * @return list<string>
     */
    private function parseCertificateDerFromPem(string $pemContents): array
    {
        $x509 = new X509;
        $certificates = [];

        $matches = [];
        preg_match_all(
            '/-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----/s',
            $pemContents,
            $matches,
        );

        foreach ($matches[1] as $base64Content) {
            $stripped = preg_replace('/\s+/', '', $base64Content);
            if (! is_string($stripped)) {
                throw new \RuntimeException('Failed to process certificate data');
            }

            $der = base64_decode($stripped, true);
            if ($der === false || $der === '') {
                throw new \RuntimeException('Failed to decode certificate DER data');
            }

            if ($x509->loadX509($der) === false) {
                throw new \RuntimeException('Unable to parse a certificate from the PEM file');
            }

            $certificates[] = $der;
        }

        return $certificates;
    }
}
