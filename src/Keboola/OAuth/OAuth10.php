<?php
namespace Keboola\OAuth;

class OAuth10 extends AbstractOAuth
{
    /**
     * @var string
     */
    protected $requestTokenUrl;

    public function __construct(array $config)
    {
        $this->requestTokenUrl = $config['request_token_url'];
        parent::__construct($config);
    }

    /**
     * @todo NEEDS app_key/secret, auth_url, request_token_url (1.0)
     * 2.0 will need redir_url along with auth_url, app_key
     */
    public function createRedirectUrl($callbackUrl)
    {
        $oauth = new \OAuth($this->appKey, $this->appSecret);
        $tokens = $oauth->getRequestToken($this->getRequestTokenUrl(), $callbackUrl);

        return [
            'url' => $this->getAuthenticateUrl($tokens["oauth_token"]),
            'sessionData' => $tokens
        ];
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
}
