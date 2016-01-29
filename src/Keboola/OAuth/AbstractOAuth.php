<?php
namespace Keboola\OAuth;

abstract class AbstractOAuth
{
    public function __construct()
    {

    }

    abstract function createRedirectUrl();

    /**
     * Give the function API info, both need auth_url, 2.0 needs app_key
     * 2.0 then needs redir_url, 1.0 needs token generated at request_token_url
     * Therefore the config should be created in createRedirectUrl to suit the case
     * getOAuthUrl (2.0)/ getAuthenticateUrl (1.0)
     * @param array $config ?
     */
    abstract function createAuthUrl();
}
