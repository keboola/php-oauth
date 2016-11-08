<?php
namespace Keboola\OAuth;

use GuzzleHttp\Client,
    GuzzleHttp\Exception\ClientException;
use function Keboola\Utils\jsonDecode;
use Keboola\Syrup\Exception\UserException;

class OAuth20 extends AbstractOAuth
{
    const GRANT_TYPE = 'authorization_code';

    /**
     * @todo NEEDS app_key/secret, auth_url, request_token_url (1.0)
     * 2.0 will need redir_url along with auth_url, app_key
     */
    public function createRedirectData($callbackUrl)
    {
        $url = $this->authUrl;
        $url = str_replace('%%redirect_uri%%', $callbackUrl, $url);
        // DEPRECATED by %%app_key%%
        $url = str_replace('%%client_id%%', $this->appKey, $url);
        $url = str_replace('%%app_key%%', $this->appKey, $url);
        return ['url' => $url];
    }

    public function createToken($callbackUrl, array $sessionData, array $query)
    {
        if (empty($query['code'])) {
            throw new UserException("'code' not returned in query from the auth API!");
        }

        $guzzle = new Client();
        try {
            $response = $guzzle->post(
                $this->tokenUrl,
                [
                    "form_params" => [
                        "client_id" => $this->appKey,
                        "client_secret" => $this->appSecret,
                        "grant_type" => self::GRANT_TYPE,
                        "redirect_uri" => $callbackUrl,
                        "code" => $query['code']
                    ],
                    'headers' => [
                        'Accept' => 'application/json',
                    ],
                ]
            );
        } catch (ClientException $e) {
            $errCode = $e->getResponse()->getStatusCode();
            if ($errCode == 400) {
                $desc = jsonDecode($e->getResponse()->getBody(true), true);
                $code = empty($desc["code"]) ? 0 : $desc["code"];
                $message = empty($desc["error_message"]) ? "Unknown error from API." : $desc["error_message"];

                throw new UserException(
                    "OAuth authentication failed[{$code}]: {$message}",
                    null,
                    [
                        'response' => $e->getResponse()->getBody()
                    ]
                );
            } else {
                throw $e;
            }
        }

        return jsonDecode($response->getBody(true));
    }
}
