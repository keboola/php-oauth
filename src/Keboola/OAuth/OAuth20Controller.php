<?php

namespace Keboola\OAuth;

use	Keboola\OAuth\Exception\UserException;
use	Symfony\Component\HttpFoundation\Response,
	Symfony\Component\HttpFoundation\Request;
use	GuzzleHttp\Client as GuzzleClient,
	GuzzleHttp\Exception\ClientException;
use	Keboola\Utils\Utils;

/**
 * {@inheritdoc}
 *
 * Handle the OAuth 2.0 authentication process
 * @todo bool $useHash to allow not using hash in case "state" is not allowed?
 */
abstract class OAuth20Controller extends OAuthController implements OAuthControllerInterface
{
	/**
	 * Default grant_type for callback
	 * @var string
	 */
	protected $grantType = "authorization_code";

	/**
	 * OAuth 2.0 token retrieval URL
	 * See (C) at @link http://www.ibm.com/developerworks/library/x-androidfacebookapi/fig03.jpg
	 * ie: https://api.example.com/oauth2/token
	 * @var string
	 */
	protected $tokenUrl = "";

	/**
	 * Create OAuth 2.0 request code URL (use CODE "response type")
	 * See (A) at @link http://www.ibm.com/developerworks/library/x-androidfacebookapi/fig03.jpg
	 * @param string $redirUrl Redirect URL
	 * @param string $clientId Application's registered Client ID
	 * @param string $hash Session verification code (use in the "state" query parameter)
	 * @return string URL
	 * ie: return "https://api.example.com/oauth2/auth?
	 *	response_type=code
	 *	&client_id={$clientId}
	 *	&redirect_uri={$redirUrl}
	 *	&scope=users.read+records.write
	 *	&state={$hash}"
	 *	(obviously without them newlines!)
	 */
	abstract protected function getOAuthUrl($redirUrl, $clientId, $hash);

	/*********************************      app-specific code end!      ***************************/

	/**
	 * @return string ClientId
	 * ie: return $this->getParam("appname", true)["client-id"];
	 *   - to get the appname: client_id parameter from parameters.yml
	 */
	protected function getClientId()
	{
		return $this->getAppParams()['client-id'];
	}

	/**
	 * @return string ClientSecret
	 * ie: return $this->getParam("appname", true)["client-secret"];
	 *   - to get the appname: client_id parameter from parameters.yml
	 */
	protected function getClientSecret()
	{
		return $this->getAppParams()['client-secret'];
	}

	/**
	 * Send the user to OAuth 2.0 authorization page
	 * {@inheritdoc}
	 *
	 * @param Request $request
	 * @return \Symfony\Component\HttpFoundation\RedirectResponse
	 */
	public function getOAuthAction(Request $request)
	{
		$this->initSession($request);

		$hash = md5(join("_", $request->request->all()) . uniqid());
		$this->sessionBag->set("hash", $hash);

		return $this->redirect(
			$this->getOAuthUrl($this->getCallbackUrl($request), $this->getClientId(), $hash),
			302,
			$this->defaultResponseHeaders
		);
	}

	/**
	 * Handle the callback action and send token to $this->tokenUrl to validate
	 * {@inheritdoc}
	 *
	 * @param Request $request
	 * @return \Symfony\Component\HttpFoundation\Response
	 */
	public function getOAuthCallbackAction(Request $request)
	{
		$this->initSessionBag();

		if ($request->query->get("state") != $this->sessionBag->get("hash")) {
			throw new UserException("Invalid session verification hash");
		}

		$guzzle = new GuzzleClient();
		try {
			$response = $guzzle->post($this->tokenUrl, array("body" => array(
				"client_id" => $this->getClientId(),
				"client_secret" => $this->getClientSecret(),
				"grant_type" => $this->grantType,
				"redirect_uri" => $this->getCallbackUrl($request),
				"code" => $request->query->get("code")
			)));
		} catch (ClientException $e) {
			$errCode = $e->getResponse()->getStatusCode();
			if ($errCode == 400) {
				$desc = json_decode($e->getResponse()->getBody(true), true);
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

		$responseData = Utils::json_decode($response->getBody(true));

		$this->storeOAuthData($responseData);
		return $this->returnResult($responseData);
	}
}
