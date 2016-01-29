<?php
namespace Keboola\OAuth;

class OAuth20 extends AbstractOAuth
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
     * @todo NEEDS app_key/secret, auth_url, request_token_url (1.0)
     * 2.0 will need redir_url along with auth_url, app_key
     */
    public function createRedirectUrl($callbackUrl)
    {
        $url = $this->authUrl;
        $url = str_replace('%%redirect_uri%%', $redirUrl, $url);
        $url = str_replace('%%client_id%%', $this->appKey, $url);
        return $url;
    }
}
