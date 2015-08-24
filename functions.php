<?php
	// SSO client support functions.
	// (C) 2015 CubicleSoft.  All Rights Reserved.

	if (!class_exists("SSO_Client"))
	{
		echo "The base class must be loaded first.";
		exit();
	}

	$sso__client = new SSO_Client;
	$sso__client->Init(isset($sso_removekeys) ? $sso_removekeys : array());

	function SSO_SendRequest($action, $options = array(), $endpoint = SSO_SERVER_ENDPOINT_URL, $apikey = SSO_SERVER_APIKEY, $secretkey = SSO_SERVER_SECRETKEY)
	{
		global $sso__client;

		return $sso__client->SendRequest($action, $options, $endpoint, $apikey, $secretkey);
	}

	function SSO_GetFullRequestURLBase()
	{
		global $sso__client;

		return $sso__client->GetFullRequestURLBase();
	}

	function SSO_LoggedIn()
	{
		global $sso__client;

		return $sso__client->LoggedIn();
	}

	function SSO_CanAutoLogin()
	{
		global $sso__client;

		return $sso__client->CanAutoLogin();
	}

	function SSO_FromSSOServer()
	{
		global $sso__client;

		return $sso__client->FromSSOServer();
	}

	function SSO_Login($lang = "", $msg = "", $extra = array(), $appurl = "")
	{
		global $sso__client;

		$sso__client->Login($lang, $msg, $extra, $appurl);
	}

	function SSO_CanRemoteLogin()
	{
		global $sso__client;

		$sso__client->CanRemoteLogin();
	}

	function SSO_RemoteLogin($userid, $fieldmap = array(), $endpoint = SSO_SERVER_ENDPOINT_URL, $apikey = SSO_SERVER_APIKEY, $secretkey = SSO_SERVER_SECRETKEY)
	{
		global $sso__client;

		$sso__client->RemoteLogin($userid, $fieldmap, $endpoint, $apikey, $secretkey);
	}

	function SSO_Logout()
	{
		global $sso__client;

		$sso__client->Logout();
	}

	function SSO_HasDBData()
	{
		global $sso__client;

		return $sso__client->HasDBData();
	}

	function SSO_LoadDBData($data)
	{
		global $sso__client;

		return $sso__client->LoadDBData($data);
	}

	function SSO_SaveDBData()
	{
		global $sso__client;

		return $sso__client->SaveDBData();
	}

	function SSO_IsSiteAdmin()
	{
		global $sso__client;

		return $sso__client->IsSiteAdmin();
	}

	function SSO_HasTag($name)
	{
		global $sso__client;

		return $sso__client->HasTag($name);
	}

	function SSO_LoadUserInfo($savefirst = false)
	{
		global $sso__client;

		return $sso__client->LoadUserInfo($savefirst);
	}

	function SSO_UserLoaded()
	{
		global $sso__client;

		return $sso__client->UserLoaded();
	}

	function SSO_GetField($key, $default = false)
	{
		global $sso__client;

		return $sso__client->GetField($key, $default);
	}

	function SSO_GetEditableFields()
	{
		global $sso__client;

		return $sso__client->GetEditableFields();
	}

	function SSO_SetField($key, $value)
	{
		global $sso__client;

		return $sso__client->SetField($key, $value);
	}

	function SSO_GetData($key, $default = false)
	{
		global $sso__client;

		return $sso__client->GetData($key, $default);
	}

	function SSO_SetData($key, $value, $maxcookielen = 50)
	{
		global $sso__client;

		return $sso__client->SetData($key, $value, $maxcookielen);
	}

	function SSO_GetMappedUserInfo($fieldmap, $object = false, $save = true)
	{
		global $sso__client;

		return $sso__client->GetMappedUserInfo($fieldmap, $object, $save);
	}

	function SSO_SaveUserInfo($usedb = false)
	{
		global $sso__client;

		return $sso__client->SaveUserInfo($usedb);
	}

	function SSO_GetUserID()
	{
		global $sso__client;

		return $sso__client->GetUserID();
	}

	function SSO_GetSecretToken()
	{
		global $sso__client;

		return $sso__client->GetSecretToken();
	}
?>