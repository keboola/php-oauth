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
     * Give the function API info, both need auth_url, 2.0 needs app_key
     * 2.0 then needs redir_url, 1.0 needs token generated at request_token_url
     * Therefore the config should be created in createRedirectUrl to suit the case
     * getOAuthUrl (2.0)/ getAuthenticateUrl (1.0)
     * @param array $config ?
     */
//     abstract function createAuthUrl();

// TODO handle callback
}
