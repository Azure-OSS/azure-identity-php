<?php

declare(strict_types=1);

namespace AzureOss\Identity;

final class AccessToken
{
    public function __construct(
        public readonly string $token,
        public readonly \DateTimeInterface $expiresOn,
        public readonly string $tokenType
    ) {}

    /** @internal */
    public static function fromTokenResponse(string $responseBody): self
    {
        $data = json_decode($responseBody, true);

        if (! is_array($data) ||
            ! array_key_exists('access_token', $data) ||
            ! is_string($data['access_token']) ||
            ! array_key_exists('expires_in', $data) ||
            ! is_numeric($data['expires_in']) ||
            ! array_key_exists('token_type', $data) ||
            ! is_string($data['token_type'])
        ) {
            throw new \RuntimeException('Unexpected response from Azure');
        }

        return new self(
            $data['access_token'],
            (new \DateTimeImmutable)->modify("+{$data['expires_in']} seconds"),
            $data['token_type'],
        );
    }
}
