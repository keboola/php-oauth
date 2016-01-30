<?php
namespace Keboola\OAuth;

abstract class AbstractOAuth
{
    /**
     * @var string
     */
    protected $appKey;

    /**
     * @var string
     */
    protected $appSecret;

    /**
     * @var string
     */
    protected $authUrl;

    /**
     * @var string
     */
    protected $tokenUrl;

    public function __construct(array $config)
    {
        $this->appKey = $config['app_key'];
        $this->appSecret = $config['app_secret'];
        $this->authUrl = $config['auth_url'];
        $this->tokenUrl = $config['token_url'];
    }

    /**
     * @param string $callbackUrl
     * @return array ['url' => '', 'sessionData' => [...]]
     */
    abstract function createRedirectData($callbackUrl);

    /**
     * 1.0: $sessionData; $request->query->get("oauth_verifier")
     * 2.0: $callbackUrl; $request->query->get('code');
     *
     * @param string $callbackUrl
     * @param array $sessionData
     * @param array $query
     */
    abstract function createToken($callbackUrl, array $sessionData, array $query);
}
