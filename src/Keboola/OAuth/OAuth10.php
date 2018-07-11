<?php
namespace Keboola\OAuth;

use Keboola\OAuth\Exception\UserException;

class OAuth10 extends AbstractOAuth
{
    /** @var string */
    protected $requestTokenUrl;

    /** @var string */
    protected $signatureMethod;

    /** @var string */
    protected $rsaPrivateKey;

    public function __construct(array $config)
    {
        $this->requestTokenUrl = $config['request_token_url'];
        $this->signatureMethod = isset($config['signature_method'])
            ? $this->validateSignatureMethod($config['signature_method'])
            : OAUTH_SIG_METHOD_HMACSHA1;
        $this->rsaPrivateKey = isset($config['rsa_private_key']) ? $config['rsa_private_key'] : null;

        parent::__construct($config);
    }

    public function createRedirectData($callbackUrl)
    {
        $tokens = $this->getOAuth()->getRequestToken($this->getRequestTokenUrl(), $callbackUrl);

        return [
            'url' => $this->getAuthenticateUrl($tokens['oauth_token']),
            'sessionData' => $tokens
        ];
    }

    public function createToken($callbackUrl, array $sessionData, array $query)
    {
        $oauth = $this->getOAuth();
        $oauth->setToken($sessionData['oauth_token'], $sessionData['oauth_token_secret']);

        return $oauth->getAccessToken($this->tokenUrl, null, $query['oauth_verifier']);
    }

    protected function getRequestTokenUrl()
    {
        return $this->requestTokenUrl;
    }

    protected function getAuthenticateUrl($oauthToken)
    {
        $url = $this->authUrl;
        $url = str_replace('%%oauth_token%%', $oauthToken, $url);
        return $url;
    }

    protected function validateSignatureMethod($method)
    {
        $supportedMethods = [
            OAUTH_SIG_METHOD_HMACSHA1,
            OAUTH_SIG_METHOD_RSASHA1,
            OAUTH_SIG_METHOD_HMACSHA256,
        ];

        if (!in_array($method, $supportedMethods)) {
            throw new UserException(sprintf(
                'Signature method "%s" not supported. Supported methods are "%s"',
                $method,
                implode(',', $supportedMethods)
            ));
        }

        return $method;
    }

    protected function getOAuth()
    {
        $oauth = new \OAuth($this->appKey, $this->appSecret, $this->signatureMethod);
        if ($this->rsaPrivateKey !== null) {
            $oauth->setRSACertificate($this->rsaPrivateKey);
        }

        return $oauth;
    }
}
