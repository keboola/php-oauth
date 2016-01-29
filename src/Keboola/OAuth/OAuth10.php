<?php
namespace Keboola\OAuth;

class OAuth10 extends AbstractOAuth
{
    public function __construct(array $config)
    {

    }

    /**
     * @todo NEEDS app_key/secret, auth_url, request_token_url (1.0)
     * 2.0 will need redir_url along with auth_url, app_key
     */
    public function createRedirectUrl()
    {
        $this->initSession($request);

        $apiKeys = $this->getAppParams();

        $oauth = new \OAuth($apiKeys["api-key"], $apiKeys["api-secret"]);

        $tokens = $oauth->getRequestToken($this->getRequestTokenUrl(), $this->getCallbackUrl($request));
        // TODO encrypt both
        $this->sessionBag->set("oauth_token", $tokens["oauth_token"]);
        $this->sessionBag->set("oauth_token_secret", $tokens["oauth_token_secret"]);

        return $this->getAuthenticateUrl($tokens["oauth_token"]);
    }

}
