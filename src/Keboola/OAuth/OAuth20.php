<?php
namespace Keboola\OAuth;

class OAuth20 extends AbstractOAuth
{
    /**
     * @todo NEEDS app_key/secret, auth_url, request_token_url (1.0)
     * 2.0 will need redir_url along with auth_url, app_key
     */
    public function createRedirectData($callbackUrl)
    {
        $url = $this->authUrl;
        $url = str_replace('%%redirect_uri%%', $callbackUrl, $url);
        $url = str_replace('%%client_id%%', $this->appKey, $url);
        return ['url' => $url];
    }
}
