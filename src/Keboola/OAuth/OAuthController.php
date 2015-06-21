<?php

namespace Keboola\OAuth;

use	Syrup\ComponentBundle\Exception\SyrupComponentException,
	Syrup\ComponentBundle\Exception\UserException,
	Syrup\ComponentBundle\Controller\BaseController;
use	Symfony\Component\HttpFoundation\Response,
	Symfony\Component\HttpFoundation\Request,
	Symfony\Component\HttpFoundation\Session\Attribute\AttributeBag,
	Symfony\Component\HttpFoundation\Session\Session;
use	Keboola\StorageApi\Client as StorageApi;
use	GuzzleHttp\Client as GuzzleClient;

/**
 * Base OAuth class defining the authentication flow.
 *
 * OAuth controllers should be called using:
 * POST: /ex-dummy/oauth
 *	form data containing
 *		"token"(StorageApi token)
 *		"config"(configuration table name)
 * -- OR --
 * GET: /ex-dummy/oauth?token=...&config=...
 *
 * @todo Separate to an OAuth bundle
 */
abstract class OAuthController extends BaseController
{
	/**
	 * ie: ex-dummy
	 * @var string
	 */
	protected $appName = "";

	/**
	 * @var StorageApi
	 */
	protected $storageApi;

	/**
	 * @var AttributeBag
	 */
	protected $sessionBag;

	protected $defaultResponseHeaders = array(
		"Content-Type" => "application/json",
		"Access-Control-Allow-Origin" => "*",
		"Connection" => "close"
	);

	/**
	 * Initialize the OAuth action.
	 * Set config, token and referrer to session
	 *
	 * @param Request $request
	 * @return \Symfony\Component\HttpFoundation\RedirectResponse
	 */
	abstract public function getOAuthAction(Request $request);

	/**
	 * Handle the callback action.
	 * Store or display tokens
	 *
	 * @param Request $request
	 * @return \Symfony\Component\HttpFoundation\Response
	 */
	abstract public function getOAuthCallbackAction(Request $request);

	/**
	 * Handle saving data returned from the OAuth process to StorageApi
	 * By default, all response data is saved as oauth.{key}:{value} pairs
	 * Override this to change which attributes to save, which to set protected etc..
	 * @param \stdClass $data Data from the OAuth response
	 * @return void
	 */
	protected function storeOAuthData($data)
	{
		$storageApi = $this->getStorageApi();

		$tableId = "sys.c-{$this->appName}." . $this->sessionBag->get("config");
		if (!$storageApi->tableExists($tableId)) {
			throw new UserException(sprintf("Configuration %s doesn't exist!", $this->sessionBag->get("config")));
		}

		foreach($data as $key => $value) {
			// Try to guess whether to save the attribute as protected or not, by looking for "token" in its name
			$protected = (strpos($key, "token") === false) ? false : true;

			$storageApi->setTableAttribute(
				$tableId,
				"oauth." . $key,
				$value,
				$protected
			);
		}
	}

	/**
	 * Reads the application configuration from parameters.yml
	 * $this->appName MUST be in format 'ex-name'!
	 * Example parameters.yml for ex-dummy:
	 * For OAuth 1.0
	 * 	parameters:
	 *		dummy:
	 *			api-key: yourApiKey
	 *			api-secret: yourApiSecret
	 * For OAuth 2.0
	 * 	parameters:
	 *		dummy:
	 *			client-id: yourClientId
	 *			client-secret: yourClientSecret
	 * @return array
	 */
	protected function getAppParams()
	{
		return $this->getParam(explode("-", $this->appName, 2)[1], true);
	}

	/**
	 * @return StorageApi
	 */
	protected function getStorageApi()
	{
		if (empty($this->storageApi)) {
			$this->storageApi = new StorageApi(array(
				"token" => $this->sessionBag->get("token"),
				"userAgent" => $this->appName
			));
		}

		return $this->storageApi;
	}

	/**
	 * Init OAuth session bag
	 *
	 * @return AttributeBag
	 */
	protected function initSessionBag()
	{
		if (!$this->sessionBag) {
			$name = str_replace("-", "", $this->appName);
			/** @var Session $session */
			$session = $this->container->get('session');
			$bag = new AttributeBag('_' . str_replace("-", "_", $this->appName));
			$bag->setName($name);
			$session->registerBag($bag);

			$this->sessionBag = $session->getBag($name);
		}

		return $this->sessionBag;
	}

	/**
	 * Initialize session and check/set mandatory fields.
	 * @param Request $request
	 */
	protected function initSession(Request $request)
	{
		if (!$request->request->has('token')) {
			throw new UserException("Missing parameter 'token'");
		}
		if (!$request->request->has('config')) {
			throw new UserException("Missing parameter 'config'");
		}

		$this->initSessionBag();
		foreach($request->request->all() as $key => $value) {
			$this->sessionBag->set($key, $value);
		}
		if ($request->request->has('returnUrl')) {
			$this->sessionBag->set("referrer", $request->request->get('returnUrl'));
		} else {
			$this->sessionBag->set("referrer", $request->server->get("HTTP_REFERER"));
		}
	}

	/**
	 * Get the current URL (used for redirect URL generation)
	 *
	 * @param Request $request
	 * @return string
	 */
	protected function getSelfUrl(Request $request)
	{
		return $request->getSchemeAndHttpHost()
			. $request->getBaseUrl()
			. $request->getPathInfo();
	}

	/**
	 * Get the callback URL
	 *
	 * @param Request $request
	 * @return string
	 */
	protected function getCallbackUrl(Request $request)
	{
		$selfUrl = $this->getSelfUrl($request);
		if (substr($selfUrl, -9) == "-callback") {
			return $selfUrl;
		} else {
			return $selfUrl . "-callback";
		}
	}

	/**
	 * Get an attribute from parameters.yml
	 *
	 * @param $name Name of the attribute
	 * @param $required (bool) Whether the attribute is mandatory (false by default)
	 * @return mixed
	 */
	protected function getParam($name, $required = false)
	{
		if (!$this->container->hasParameter($name)) {
			if ($required) {
				throw new SyrupComponentException(500, "Parameter '{$name}' not set in parameters.yml");
			} else {
				return null;
			}
		} else {
			return $this->container->getParameter($name);
		}
	}

	/**
	 * Handle a GET request with token&config parameters in URL
	 * @param Request $request
	 * @return \Symfony\Component\HttpFoundation\Response
	 */
	public function externalAuthAction(Request $request)
	{
		if (!$request->query->has('token')) {
			throw new UserException("Missing parameter 'token'");
		}
		if (!$request->query->has('config')) {
			throw new UserException("Missing parameter 'config'");
		}

		$request->request->set('token', $request->query->get('token'));
		$request->request->set('config', $request->query->get('config'));

		return $this->getOAuthAction($request);
	}

	/**
	 * Return Decide whether to return a redirect to "referrer" or a JSON encoded response
	 * @param array|stdClass $data Data to be returned in the JSON
	 * @param string $status A status to be included in the result.
	 * 					If the response contains a "status" key, it will replace the status
	 * @return \Symfony\Component\HttpFoundation\Response
	 */
	protected function returnResult($data, $status = "ok")
	{
		$referrer = $this->sessionBag->get("referrer");
		if (!empty($referrer)) {
			return $this->redirect($referrer);
		} else {
			return new Response(json_encode(array_replace(array("status" => $status), (array) $data)), 200, $this->defaultResponseHeaders);
		}
	}
}
