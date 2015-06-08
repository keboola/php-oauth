<?php
namespace Keboola\OAuth;

use	Symfony\Component\HttpFoundation\Request;

/**
 * OAuthControllerInterface
 * Defines methods required for standard OAuth 1.0 and 2.0 controlelrs
 *
 * @author Ondrej Vana <kachna@keboola.com>
 */
interface OAuthControllerInterface
{
	/**
	 * Send user to OAuth authorization page
	 *
	 * @param Request $request
	 * @return \Symfony\Component\HttpFoundation\RedirectResponse
	 */
	public function getOAuthAction(Request $request);

	/**
	 * Handle the callback action
	 *
	 * @param Request $request
	 * @return \Symfony\Component\HttpFoundation\Response
	 */
	public function getOAuthCallbackAction(Request $request);

	/**
	 * Handle a GET request with token&config parameters in URL
	 *
	 * @param Request $request
	 * @return \Symfony\Component\HttpFoundation\Response
	 */
	public function externalAuthAction(Request $request);
}
