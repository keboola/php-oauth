<?php

namespace Keboola\OAuth;

use	Symfony\Component\HttpFoundation\Response,
	Symfony\Component\HttpFoundation\Request;

/**
 * {@inheritdoc}
 *
 * Uses OAuth 1.0
 * Authentication flow diagram: @link http://oauth.net/core/diagram.png
 * Implemented using PHP's OAuth extension:
 * @link http://pecl.php.net/package/oauth
 * @TODO use guzzle's OAuth instead of PHP ext
 */
abstract class OAuth10Controller extends OAuthController implements OAuthControllerInterface
{
	/**
	 * See (A) at @link http://oauth.net/core/diagram.png
	 * ie: https://api.example.com/oauth/request_token
	 * @var string
	 */
	protected $requestTokenUrl = "";

	/**
	 * See (E) at http://oauth.net/core/diagram.png
	 * ie: https://api.example.com/oauth/access_token
	 * @var string
	 */
	protected $accessTokenUrl = "";

	/**
	 * Create OAuth /authenticate URL
	 * See (C) at @link http://oauth.net/core/diagram.png
	 * @param string $redirUrl Redirect URL
	 * @return string URL
	 * ie: return "https://api.example.com/oauth/authenticate?oauth_token={$oauthToken}"
	 */
	abstract protected function getAuthenticateUrl($oauthToken);

	/**
	 * obtain the request_tokens and redirect for permission to get the token_verifier
	 * {@inheritdoc}
	 *
	 * @param Request $request
	 * @return \Symfony\Component\HttpFoundation\Response
	 **/
	public function getOAuthAction(Request $request)
	{
		$this->initSession($request);

		$apiKeys = $this->getAppParams();

		$oauth = new \OAuth($apiKeys["api-key"], $apiKeys["api-secret"]);

		$tokens = $oauth->getRequestToken($this->requestTokenUrl, $this->getCallbackUrl($request));
		$this->sessionBag->set("oauth_token", $tokens["oauth_token"]);
		$this->sessionBag->set("oauth_token_secret", $tokens["oauth_token_secret"]);

		return $this->redirect(
			$this->getAuthenticateUrl($tokens["oauth_token"])
// 			302,
// 			["Authorization" => $oauth->getRequestHeader("POST", $this->requestTokenUrl)]
		);
	}

	/**
	 * Get the access_token from oauth_verifier and request_tokens
	 * {@inheritdoc}
	 *
	 * @param Request $request
	 * @return \Symfony\Component\HttpFoundation\Response
	 **/
	public function getOAuthCallbackAction(Request $request)
	{
		$this->initSessionBag();

		$apiKeys = $this->getAppParams();
		$oauth = new \OAuth($apiKeys["api-key"], $apiKeys["api-secret"]);
		$oauth->setToken($this->sessionBag->get("oauth_token"), $this->sessionBag->get("oauth_token_secret"));

		$oauthResponse = $oauth->getAccessToken($this->accessTokenUrl, null, $request->query->get("oauth_verifier"));

		$this->storeOAuthData($oauthResponse);
		return $this->returnResult($oauthResponse);
	}
}
