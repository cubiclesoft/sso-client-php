<?php
	// Single Sign-On Client
	// (C) 2014 CubicleSoft.  All Rights Reserved.

	if (file_exists("config.php"))  exit();

	require_once "support/debug.php";
	require_once "support/str_basics.php";
	require_once "support/page_basics.php";
	require_once "support/sso_functions.php";
	require_once "support/sso_blowfish.php";
	require_once "support/sso_aes.php";
	require_once "support/sso_random.php";

	SetDebugLevel();
	Str::ProcessAllInput();

	// Allow developers to inject code here.  For example, IP address restriction logic.
	if (file_exists("install_hook.php"))  require_once "install_hook.php";

	if (isset($_REQUEST["action"]) && $_REQUEST["action"] == "checklist")
	{
?>
	<table align="center">
		<tr class="head"><th>Test</th><th>Passed?</th></tr>
		<tr class="row">
			<td>PHP 5.4.x or later</td>
			<td align="right">
<?php
		if ((double)phpversion() < 5.4)  echo "<span class=\"error\">No</span><br /><br />The server is running PHP " . phpversion() . ".  The installation may succeed but the rest of the Single Sign-On Client will be broken.  You will be unable to use this product.  Running outdated versions of PHP poses a serious website security risk.  Please contact your system administrator to upgrade your PHP installation.";
		else  echo "<span class=\"success\">Yes</span>";
?>
			</td>
		</tr>
		<tr class="row altrow">
			<td>PHP 'safe_mode' off</td>
			<td align="right">
<?php
		if (ini_get('safe_mode'))  echo "<span class=\"error\">No</span><br /><br />PHP is running with 'safe_mode' enabled.  You will probably get additional failures below relating to file/directory creation.  This setting is generally accepted as a poor security solution that doesn't work and is deprecated.  Please turn it off.  If you are getting errors below, can't change this setting, and the fixes below aren't working, you may need to contact your hosting service provider.";
		else  echo "<span class=\"success\">Yes</span>";
?>
			</td>
		</tr>
		<tr class="row">
			<td>Able to create files in ./</td>
			<td align="right">
<?php
		if (file_put_contents("test.dat", "a") === false)  echo "<span class=\"error\">No</span><br /><br />chmod 777 on the directory may fix the problem.";
		else if (!unlink("test.dat"))  echo "<span class=\"error\">No</span><br /><br />Unable to delete test file.  chmod 777 on the directory may fix the problem.";
		else  echo "<span class=\"success\">Yes</span>";
?>
			</td>
		</tr>
		<tr class="row altrow">
			<td>$_SERVER["REQUEST_URI"] supported</td>
			<td align="right">
<?php
		if (!isset($_SERVER["REQUEST_URI"]))  echo "<span class=\"error\">No</span><br /><br />Server does not support this feature.  The installation may fail and the site might not work.";
		else  echo "<span class=\"success\">Yes</span>";
?>
			</td>
		</tr>
		<tr class="row">
			<td>PHP 'register_globals' off</td>
			<td align="right">
<?php
		if (ini_get('register_globals'))  echo "<span class=\"error\">No</span><br /><br />PHP is running with 'register_globals' enabled.  This setting is generally accepted as a major security risk and is deprecated.  Please turn it off by editing the php.ini file for your site - you may need to contact your hosting provider to accomplish this task.";
		else  echo "<span class=\"success\">Yes</span>";
?>
			</td>
		</tr>
		<tr class="row altrow">
			<td>PHP 'magic_quotes_gpc' off</td>
			<td align="right">
<?php
		if (get_magic_quotes_gpc())  echo "<span class=\"error\">No</span><br /><br />PHP is running with 'magic_quotes_gpc' enabled.  This setting is generally accepted as a security risk AND causes all sorts of non-security-related problems.  It is also deprecated.  Please turn it off by editing the php.ini file for your site - you may need to contact your hosting provider to accomplish this task.";
		else  echo "<span class=\"success\">Yes</span>";
?>
			</td>
		</tr>
		<tr class="row">
			<td>PHP 'magic_quotes_sybase' off</td>
			<td align="right">
<?php
		if (ini_get('magic_quotes_sybase'))  echo "<span class=\"error\">No</span><br /><br />PHP is running with 'magic_quotes_sybase' enabled.  This setting is generally accepted as a security risk AND causes all sorts of non-security-related problems.  It is also deprecated.  Please turn it off by editing the php.ini file for your site - you may need to contact your hosting provider to accomplish this task.";
		else  echo "<span class=\"success\">Yes</span>";
?>
			</td>
		</tr>
		<tr class="row altrow">
			<td>Installation over SSL</td>
			<td align="right">
<?php
		if (!BB_IsSSLRequest())  echo "<span class=\"error\">No</span><br /><br />While Single Sign-On Client will install and run without using HTTPS/SSL, think about the implications of network sniffing access tokens, who will have access to the system, and what they can do in the system.  SSL certificates can be obtained for free.  Proceed only if this major security risk is acceptable.";
		else  echo "<span class=\"success\">Yes</span>";
?>
			</td>
		</tr>
		<tr class="row altrow">
			<td>Crypto-safe CSPRNG available</td>
			<td align="right">
<?php
		try
		{
			$rng = new SSO_CSPRNG(true);
			echo "<span class=\"success\">Yes</span>";
		}
		catch (Exception $e)
		{
			echo "<span class=\"error\">No</span><br /><br />Installation will fail.  Please ask your system administrator to install a supported PHP extension (e.g. OpenSSL, Mcrypt).";
		}
?>
			</td>
		</tr>
		<tr class="head">
			<th>Supported PHP functions</th>
			<th>&nbsp;</th>
		</tr>
<?php
		$functions = array(
			"fsockopen" => "Web functions",
			"json_decode" => "JSON decoding support functions",
			"mcrypt_module_open" => "Mcrypt cryptographic support functions",
			"openssl_open" => "OpenSSL extension support",
		);

		$x = 0;
		foreach ($functions as $function => $info)
		{
			echo "<tr class=\"row" . ($x % 2 ? " altrow" : "") . "\"><td>" . htmlspecialchars($function) . "</td><td align=\"right\">" . (function_exists($function) ? "<span class=\"success\">Yes</span>" : "<span class=\"error\">No</span><br /><br />Single Sign-On Client will be unable to use " . $info . ".  The installation might succeed but the product will not function at all or have terrible performance.") . "</td></tr>\n";
			$x++;
		}
?>
	</table>
<?php
	}
	else if (isset($_REQUEST["action"]) && $_REQUEST["action"] == "baseoptstest")
	{
		// Test connectivity to the SSO server.
		define("SSO_CLIENT_ROOT_PATH", str_replace("\\", "/", dirname(__FILE__)));
		define("SSO_CLIENT_SUPPORT_PATH", "support");
		define("SSO_CLIENT_LANG_PATH", "lang");
		$sso_client = new SSO_Client;
		if ($_REQUEST["default_lang"] == "")  $result = array("success" => true);
		else  $result = $sso_client->SetLanguage(SSO_CLIENT_ROOT_PATH . "/" . SSO_CLIENT_LANG_PATH . "/", $_REQUEST["default_lang"]);

		if ($result["success"])  echo "<span class=\"success\">Default language selection looks okay.</span><br />";
		else  echo "<span class=\"error\">Default language selection has a problem:  " . htmlspecialchars($result["error"]) . "</span><br />";

		define("SSO_CLIENT_PROXY_X_FORWARDED_FOR", $_REQUEST["sso_proxy_x_forwarded_for"]);
		define("SSO_CLIENT_PROXY_CLIENT_IP", $_REQUEST["sso_proxy_client_ip"]);
		define("SSO_CLIENT_PROXY_URL", $_REQUEST["sso_proxy_url"]);
		define("SSO_CLIENT_PROXY_CONNECT", (bool)(int)$_REQUEST["sso_proxy_connect"]);
		define("SSO_SERVER_ENDPOINT_URL", $_REQUEST["url"]);
		define("SSO_SERVER_APIKEY", $_REQUEST["apikey"]);
		define("SSO_SERVER_SECRETKEY", $_REQUEST["secretkey"]);

		if (SSO_SERVER_ENDPOINT_URL == "")  echo "<span class=\"error\">'SSO Server Endpoint URL' is empty.</span><br />";
		else if (SSO_SERVER_APIKEY == "")  echo "<span class=\"error\">'SSO Server API Key' is empty.</span><br />";
		else if (SSO_SERVER_SECRETKEY == "")  echo "<span class=\"error\">'SSO Server Secret Key' is empty.</span><br />";
		else
		{
			$result = $sso_client->SendRequest("test");
			if ($result["success"])  echo "<span class=\"success\">Successfully connected to the SSO server.</span><br />";
			else  echo "<span class=\"error\">Failed to connect to the SSO server.  Error:  " . htmlspecialchars($result["error"]) . (isset($result["info"]) ? "  Info:  " . htmlspecialchars($result["info"]) : "") . "</span><br />";
		}

		// Test cookie information.
		$cookiename = preg_replace('/\s+/', "_", trim(preg_replace('/[^A-Za-z0-9]/', " ", $_REQUEST["cookie_name"])));

		if ($_REQUEST["cookie_name"] == "")  echo "<span class=\"error\">'SSO Client Cookie Name' must not be empty or use invalid characters.</span><br />";
		else if ($_REQUEST["cookie_name"] == "sso_")  echo "<span class=\"warning\">'SSO Client Cookie Name' is set to the default name.  You should consider making it specific to your application.</span><br />";
		else if ($_REQUEST["cookie_name"] == "sso_server")  echo "<span class=\"error\">'SSO Client Cookie Name' is set to a reserved name that may cause problems.</span><br />";
		else if ($cookiename != $_REQUEST["cookie_name"])  echo "<span class=\"warning\">'SSO Client Cookie Name' will evaluate to '" . htmlspecialchars($cookiename) . "'.  This may not be what you entered or produce unintentional results.</span><br />";
		else  echo "<span class=\"success\">The 'SSO Client Cookie Name' looks okay.</span><br />";

		$url = dirname(BB_GetRequestURLBase());
		if (substr($url, -1) != "/")  $url .= "/";

		if (substr($_REQUEST["cookie_path"], -1) != "/")  echo "<span class=\"error\">'SSO Client Cookie Path' does not have a trailing '/' character.  This can cause problems in some browsers.</span><br />";
		else if ($_REQUEST["cookie_path"] == $url)  echo "<span class=\"warning\">'SSO Client Cookie Path' is set to the default.  This is probably incorrect.  It should point to the root URL path (no domain) of your web application to avoid an infinite sign in loop.</span><br />";
		else  echo "<span class=\"success\">The 'SSO Client Cookie Path' looks okay.</span><br />";

		function BaseoptstestReadableTime($len)
		{
			$info = "";

			$len = (int)$len;

			$len2 = (int)($len / 31536000);
			$len = $len % 31536000;
			if ($len2)  $info .= ($info != "" ? ", " : "") . $len2 . ($len2 == 1 ? " year" : " years");

			$len2 = (int)($len / 86400);
			$len = $len % 86400;
			if ($len2)  $info .= ($info != "" ? ", " : "") . $len2 . ($len2 == 1 ? " day" : " days");

			$len2 = (int)($len / 3600);
			$len = $len % 3600;
			if ($len2)  $info .= ($info != "" ? ", " : "") . $len2 . ($len2 == 1 ? " hour" : " hours");

			$len2 = (int)($len / 60);
			$len = $len % 60;
			if ($len2)  $info .= ($info != "" ? ", " : "") . $len2 . ($len2 == 1 ? " min" : " mins");

			$len2 = $len;
			if ($len2)  $info .= ($info != "" ? ", " : "") . $len2 . ($len2 == 1 ? " sec" : " secs");

			return $info;
		}

		// Test timeout information.
		if ((int)$_REQUEST["cookie_timeout"] < 0)  echo "<span class=\"error\">'SSO Client Cookie Timeout' is less than 0.</span><br />";
		else if ((int)$_REQUEST["cookie_check"] < 0)  echo "<span class=\"error\">'SSO Client Cookie Validation Check' is less than 0.</span><br />";
		else if ((int)$_REQUEST["server_timeout"] < 0)  echo "<span class=\"error\">'SSO Server Session Timeout' is less than 0.</span><br />";
		else if ((int)$_REQUEST["server_timeout"] < (int)$_REQUEST["cookie_check"])  echo "<span class=\"error\">'SSO Server Session Timeout' is less than 'SSO Client Cookie Validation Check'.</span><br />";
		else if ((int)$_REQUEST["cookie_timeout"] > 0 && (int)$_REQUEST["server_timeout"] > (int)$_REQUEST["cookie_timeout"])  echo "<span class=\"error\">'SSO Server Session Timeout' is greater than 'SSO Client Cookie Timeout'.</span><br />";
		else
		{
			echo "<span class=\"success\">The timeout information looks okay.</span><br />";

			echo "<br />";
			echo "<b>SSO Server session length:  " . BaseoptstestReadableTime($_REQUEST["server_timeout"]) . ".</b><br />";
			echo "<b>Sessions will be validated every:  " . BaseoptstestReadableTime($_REQUEST["cookie_check"]) . ".</b><br />";
			echo "<b>SSO Client cookies will expire/invalidate:  " . ($_REQUEST["cookie_timeout"] > 0 ? BaseoptstestReadableTime($_REQUEST["cookie_timeout"]) . ($_REQUEST["cookie_exit_timeout"] > 0 ? " OR when the browser is closed, whichever comes first." : ".") : "When the browser is closed.") . "</b><br />";
			echo "<br />";
			echo "Note:  SSO Client cookie length doesn't matter as much as SSO Server session length and the amount of time that passes between session validations.<br />";
		}
	}
	else if (isset($_REQUEST["action"]) && $_REQUEST["action"] == "install")
	{
		function InstallError($message)
		{
			echo "<span class=\"error\">" . $message . "  Click 'Prev' below to go back and correct the problem.</span>";
			echo "<script type=\"text/javascript\">InstallFailed();</script>";

			exit();
		}

		function InstallWarning($message)
		{
			echo "<span class=\"warning\">" . $message . "</span><br />";
		}

		function InstallSuccess($message)
		{
			echo "<span class=\"success\">" . $message . "</span><br />";
		}

		// Set up page-level calculation variables.
		define("SSO_CLIENT_ROOT_PATH", str_replace("\\", "/", dirname(__FILE__)));

		$url = dirname(BB_GetRequestURLBase());
		if (substr($url, -1) == "/")  $url = substr($url, 0, -1);
		define("SSO_CLIENT_ROOT_URL", $url);

		if (substr($_REQUEST["sso_cookie_path"], -1) != "/")  InstallError("'SSO Client Cookie Path' does not have a trailing '/' character.  This can cause problems in some browsers.");

		$cookiename = preg_replace('/\s+/', "_", trim(preg_replace('/[^A-Za-z0-9]/', " ", $_REQUEST["sso_cookie_name"])));

		if ($cookiename == "")  InstallError("'SSO Client Cookie Name' must not be empty or use invalid characters.");
		else if ($cookiename == "sso_")  InstallWarning("'SSO Client Cookie Name' is set to the default name.  You should consider reinstalling the SSO Client and making it specific to your application.");
		else if ($cookiename == "sso_server")  InstallError("'SSO Client Cookie Name' is set to a reserved name that may cause problems.");

		$cookieurl = dirname(BB_GetRequestURLBase());
		if (substr($cookieurl, -1) != "/")  $cookieurl .= "/";
		if ($_REQUEST["sso_cookie_path"] == $cookieurl)  InstallWarning("'SSO Client Cookie Path' is set to the default.  This is probably incorrect.  It should point to the root URL path (no domain) of your web application to avoid an infinite sign in loop.");

		if ((int)$_REQUEST["sso_cookie_timeout"] < 0)  InstallError("'SSO Client Cookie Timeout' is less than 0.");
		if ((int)$_REQUEST["sso_cookie_check"] < 0)  InstallError("'SSO Client Cookie Validation Check' is less than 0.");
		if ((int)$_REQUEST["sso_server_session_timeout"] < 0)  InstallError("'SSO Server Session Timeout' is less than 0.");
		if ((int)$_REQUEST["sso_server_session_timeout"] < (int)$_REQUEST["sso_cookie_check"])  InstallError("'SSO Server Session Timeout' is less than 'SSO Client Cookie Validation Check'.");
		if ((int)$_REQUEST["sso_cookie_timeout"] > 0 && (int)$_REQUEST["sso_server_session_timeout"] > (int)$_REQUEST["sso_cookie_timeout"])  InstallError("'SSO Server Session Timeout' is greater than 'SSO Client Cookie Timeout'.");
		if ($_REQUEST["sso_server_endpoint_url"] == "")  InstallError("'SSO Server Endpoint URL' is empty.");
		if ($_REQUEST["sso_server_apikey"] == "")  InstallError("'SSO Server API Key' is empty.");
		if ($_REQUEST["sso_server_secretkey"] == "")  InstallError("'SSO Server Secret Key' is empty.");

		// Generate random seeds.
		$rng = new SSO_CSPRNG(true);
		for ($x = 0; $x < 16; $x++)
		{
			$seed = $rng->GenerateToken(128);
			if ($seed === false)  InstallError("Seed generation failed.");

			define("SSO_CLIENT_RAND_SEED" . ($x ? $x + 1 : ""), $seed);
		}

		// Set up the main configuration file.
		$data = "<" . "?php\n";
		$data .= "\tdefine(\"SSO_CLIENT_ROOT_PATH\", " . var_export(SSO_CLIENT_ROOT_PATH, true) . ");\n";
		$data .= "\tdefine(\"SSO_CLIENT_ROOT_URL\", " . var_export(SSO_CLIENT_ROOT_URL, true) . ");\n";
		$data .= "\tdefine(\"SSO_CLIENT_SUPPORT_PATH\", \"support\");\n";
		$data .= "\tdefine(\"SSO_CLIENT_LANG_PATH\", \"lang\");\n";
		$data .= "\tdefine(\"SSO_CLIENT_DEFAULT_LANG\", " . var_export($_REQUEST["sso_default_lang"], true) . ");\n";
		$data .= "\tdefine(\"SSO_CLIENT_PROXY_X_FORWARDED_FOR\", " . var_export($_REQUEST["sso_proxy_x_forwarded_for"], true) . ");\n";
		$data .= "\tdefine(\"SSO_CLIENT_PROXY_CLIENT_IP\", " . var_export($_REQUEST["sso_proxy_client_ip"], true) . ");\n";
		$data .= "\tdefine(\"SSO_COOKIE_NAME\", " . var_export($cookiename, true) . ");\n";
		$data .= "\tdefine(\"SSO_COOKIE_PATH\", " . var_export($_REQUEST["sso_cookie_path"], true) . ");\n";
		$data .= "\tdefine(\"SSO_COOKIE_TIMEOUT\", " . (int)$_REQUEST["sso_cookie_timeout"] . ");\n";
		$data .= "\tdefine(\"SSO_COOKIE_EXIT_TIMEOUT\", " . var_export($_REQUEST["sso_cookie_exit_timeout"] == 1, true) . ");\n";
		$data .= "\tdefine(\"SSO_COOKIE_SSL_ONLY\", " . var_export($_REQUEST["sso_cookie_ssl_only"] == 1, true) . ");\n";
		$data .= "\tdefine(\"SSO_COOKIE_RESET_IPADDR_CHANGES\", " . var_export($_REQUEST["sso_cookie_reset_ipaddr_changes"] == 1, true) . ");\n";
		$data .= "\tdefine(\"SSO_COOKIE_CHECK\", " . (int)$_REQUEST["sso_cookie_check"] . ");\n";
		$data .= "\tdefine(\"SSO_COOKIE_CIPHER\", " . var_export($_REQUEST["sso_cookie_cipher"], true) . ");\n";
		$data .= "\tdefine(\"SSO_COOKIE_DUAL_ENCRYPT\", " . var_export($_REQUEST["sso_cookie_dual_encrypt"] == 1, true) . ");\n";
		$data .= "\tdefine(\"SSO_SERVER_ENDPOINT_URL\", " . var_export($_REQUEST["sso_server_endpoint_url"], true) . ");\n";
		$data .= "\tdefine(\"SSO_SERVER_APIKEY\", " . var_export($_REQUEST["sso_server_apikey"], true) . ");\n";
		$data .= "\tdefine(\"SSO_SERVER_SECRETKEY\", " . var_export($_REQUEST["sso_server_secretkey"], true) . ");\n";
		$data .= "\tdefine(\"SSO_SERVER_SESSION_TIMEOUT\", " . (int)$_REQUEST["sso_server_session_timeout"] . ");\n";
		$data .= "\tdefine(\"SSO_CLIENT_DB_CIPHER\", " . var_export($_REQUEST["sso_db_cipher"], true) . ");\n";
		$data .= "\tdefine(\"SSO_CLIENT_DB_DUAL_ENCRYPT\", " . var_export($_REQUEST["sso_db_dual_encrypt"] == 1, true) . ");\n";
		$data .= "\tdefine(\"SSO_CLIENT_ACCEPT_SITE_ADMIN\", " . var_export($_REQUEST["sso_accept_site_admin"] == 1, true) . ");\n";
		$data .= "\tdefine(\"SSO_CLIENT_CHECK_SITE_ADMIN\", " . var_export($_REQUEST["sso_check_site_admin"] == 1, true) . ");\n";
		$data .= "\tdefine(\"SSO_CLIENT_PROXY_URL\", " . var_export($_REQUEST["sso_proxy_url"], true) . ");\n";
		$data .= "\tdefine(\"SSO_CLIENT_PROXY_CONNECT\", " . var_export($_REQUEST["sso_proxy_connect"] == 1, true) . ");\n";
		$data .= "\tdefine(\"SSO_CLIENT_RAND_SEED\", " . var_export(SSO_CLIENT_RAND_SEED, true) . ");\n";
		$data .= "\tdefine(\"SSO_CLIENT_RAND_SEED2\", " . var_export(SSO_CLIENT_RAND_SEED2, true) . ");\n";
		$data .= "\tdefine(\"SSO_CLIENT_RAND_SEED3\", " . var_export(SSO_CLIENT_RAND_SEED3, true) . ");\n";
		$data .= "\tdefine(\"SSO_CLIENT_RAND_SEED4\", " . var_export(SSO_CLIENT_RAND_SEED4, true) . ");\n";
		$data .= "\tdefine(\"SSO_CLIENT_RAND_SEED5\", " . var_export(SSO_CLIENT_RAND_SEED5, true) . ");\n";
		$data .= "\tdefine(\"SSO_CLIENT_RAND_SEED6\", " . var_export(SSO_CLIENT_RAND_SEED6, true) . ");\n";
		$data .= "\tdefine(\"SSO_CLIENT_RAND_SEED7\", " . var_export(SSO_CLIENT_RAND_SEED7, true) . ");\n";
		$data .= "\tdefine(\"SSO_CLIENT_RAND_SEED8\", " . var_export(SSO_CLIENT_RAND_SEED8, true) . ");\n";
		$data .= "\tdefine(\"SSO_CLIENT_RAND_SEED9\", " . var_export(SSO_CLIENT_RAND_SEED9, true) . ");\n";
		$data .= "\tdefine(\"SSO_CLIENT_RAND_SEED10\", " . var_export(SSO_CLIENT_RAND_SEED10, true) . ");\n";
		$data .= "\tdefine(\"SSO_CLIENT_RAND_SEED11\", " . var_export(SSO_CLIENT_RAND_SEED11, true) . ");\n";
		$data .= "\tdefine(\"SSO_CLIENT_RAND_SEED12\", " . var_export(SSO_CLIENT_RAND_SEED12, true) . ");\n";
		$data .= "\tdefine(\"SSO_CLIENT_RAND_SEED13\", " . var_export(SSO_CLIENT_RAND_SEED13, true) . ");\n";
		$data .= "\tdefine(\"SSO_CLIENT_RAND_SEED14\", " . var_export(SSO_CLIENT_RAND_SEED14, true) . ");\n";
		$data .= "\tdefine(\"SSO_CLIENT_RAND_SEED15\", " . var_export(SSO_CLIENT_RAND_SEED15, true) . ");\n";
		$data .= "\tdefine(\"SSO_CLIENT_RAND_SEED16\", " . var_export(SSO_CLIENT_RAND_SEED16, true) . ");\n";
		$data .= "?" . ">";
		if (file_put_contents("config.php", $data) === false)  InstallError("Unable to create the configuration file.");
		InstallSuccess("Successfully created the configuration file.");

		InstallSuccess("The installation completed successfully.");

?>
		<br />
		Next:  Start using Single-Sign On Client<br />
		(Follow the <a href="http://barebonescms.com/documentation/sso/">instructions</a> to learn how to use the SSO Client.)<br />
<?php
	}
	else
	{
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<title>Single Sign-On Client Installer</title>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<link rel="stylesheet" href="support/install.css" type="text/css" />
<script type="text/javascript" src="support/jquery-1.11.0.min.js"></script>

<script type="text/javascript">
function Page(curr, next)
{
	$('#page' + curr).hide();
	$('#page' + next).fadeIn('normal');

	return false;
}
</script>

</head>
<body>
<noscript><span class="error">Er...  You need Javascript enabled to install Single Sign-On (SSO) Client.</span></noscript>
<form id="installform" method="post" enctype="multipart/form-data" action="install.php" accept-charset="utf-8">
<input type="hidden" name="action" value="install" />
<div id="main">
	<div id="page1" class="box">
		<h1>Single Sign-On Client Installer</h1>
		<h3>Welcome to the Single Sign-On Client installer.</h3>
		<div class="boxmain">
			If you are looking to implement a centralized account management and login system for one or more domains,
			bring disparate login systems together under a unified system, and easily manage all aspects of a user account,
			then this is most likely what you are looking for:<br /><br />

			<div class="indent">
				A self-contained, centralized account management server that can sit on any domain with tools
				to easily manage user fields and access permissions, with multiple signup and sign in options,
				and easy-to-use client functions to sign in and extract information from the server in a
				secure manner.  Or more simply put:  Do you need a login system that rocks?
			</div>
			<br />

			If that sounds like you, Single Sign-On (SSO) is the answer.  Just click "Next" below to get started.
		</div>

		<div class="boxbuttons">
			<a href="#" onclick="return Page(1, 2);">Next &raquo;</a>
		</div>
	</div>

	<div id="page2" class="box" style="display: none;">
		<h1>Single Sign-On Client Requirements</h1>
		<h3>The Single Sign-On Client system requirements.</h3>
		<div class="boxmain">
			In order to use Single Sign-On (SSO) Client, you will need to meet these logistical requirements:<br />
			<ul>
				<li>Someone who knows PHP (a PHP programmer)</li>
			</ul>

			You will also need to meet these technical requirements (most of these are auto-detected by this installation wizard):<br />
			<ul>
				<li><a href="http://www.php.net/" target="_blank">PHP 5.4.x or later</a> (preferably the latest)</li>
				<li><a href="http://barebonescms.com/documentation/sso/" target="_blank">A valid Single Sign-On (SSO) Server API key and secret</a></li>
			</ul>
		</div>

		<div class="boxbuttons">
			<a href="#" onclick="return Page(2, 1);">&laquo; Prev</a> | <a href="#" onclick="return Page(2, 3);">Next &raquo;</a>
		</div>
	</div>

	<div id="page3" class="box" style="display: none;">
		<h1>Single Sign-On Client Checklist</h1>
		<h3>The Single Sign-On Client compatability checklist.</h3>
		<div class="boxmain">
			Before beginning the installation, you should check to make sure that the server meets or exceeds
			the basic technical requirements.  Below is the checklist for compatability with Single Sign-On (SSO) Client.<br /><br />

			<div id="checklist"></div>
			<br />

			<script type="text/javascript">
			function RefreshChecklist()
			{
				$('#checklist').load('install.php', { 'action' : 'checklist' });

				return false;
			}

			RefreshChecklist();
			</script>

			<a href="#" onclick="return RefreshChecklist();">Refresh the checklist</a><br /><br />

			NOTE:  You are allowed to install Single Sign-On (SSO) Client even if you don't meet the requirements above.  Just don't complain if your
			installation or this installer does not work.  Each web server is different - there is no way to satisfy all servers
			without a ton of code.  Besides, you may be able to get away with some missing things for some websites.
		</div>

		<div class="boxbuttons">
			<a href="#" onclick="return Page(3, 2);">&laquo; Prev</a> | <a href="#" onclick="return Page(3, 4);">Next &raquo;</a>
		</div>
	</div>

	<div id="page4" class="box" style="display: none;">
		<h1>Single Sign-On Client Setup</h1>
		<h3>Set up Single Sign-On (SSO) Client required options.</h3>
		<div class="boxmain">
			Set up the Single Sign-On (SSO) Client required options.<br /><br />

			<div class="formfields">
				<div class="formitem">
					<div class="formitemtitle">SSO Server Endpoint URL</div>
					<input class="text" id="sso_server_endpoint_url" type="text" name="sso_server_endpoint_url" value="" />
					<div class="formitemdesc">The Endpoint URL to use from the SSO Server.  This may be obtained by logging into the SSO Server and going into 'Manage API Keys'.</div>
				</div>
				<div class="formitem">
					<div class="formitemtitle">SSO Server API Key</div>
					<input class="text" id="sso_server_apikey" type="text" name="sso_server_apikey" value="" />
					<div class="formitemdesc">The API key for this client instance.</div>
				</div>
				<div class="formitem">
					<div class="formitemtitle">SSO Server Secret Key</div>
					<input class="text" id="sso_server_secretkey" type="text" name="sso_server_secretkey" value="" />
					<div class="formitemdesc">The secret key for the API key.</div>
				</div>
				<div class="formitem">
					<div class="formitemtitle">SSO Server Session Timeout</div>
					<input class="text" id="sso_server_session_timeout" type="text" name="sso_server_session_timeout" value="604800" />
					<div class="formitemdesc">How long the SSO Server session data is valid for without a successful SSO Client Validation Check (in seconds).  Five minutes (300 seconds) is the minimum the SSO server supports.</div>
				</div>
				<div class="formitem">
					<div class="formitemtitle">SSO Client Cookie Name</div>
					<input class="text" id="sso_cookie_name" type="text" name="sso_cookie_name" value="<?php echo htmlspecialchars(isset($_REQUEST["cookie_name"]) ? $_REQUEST["cookie_name"] : "sso_"); ?>" />
					<div class="formitemdesc">The name of the session cookie to use in the web browser for this SSO Client instance.  There should be one SSO Client instance per application.  Valid characters are A-Z, a-z, 0-9, and underscore '_'.</div>
				</div>
<?php
		$url = dirname(BB_GetRequestURLBase());
		if (substr($url, -1) != "/")  $url .= "/";
?>
				<div class="formitem">
					<div class="formitemtitle">SSO Client Cookie Path</div>
					<input class="text" id="sso_cookie_path" type="text" name="sso_cookie_path" value="<?php echo htmlspecialchars(isset($_REQUEST["cookie_path"]) ? $_REQUEST["cookie_path"] : $url); ?>" />
					<div class="formitemdesc">The base path where the SSO Client cookie will be applicable.  If you are directly installing the SSO Client (i.e. not from within a plugin), then you probably need to change this to avoid an infinite loop in your application.</div>
				</div>
				<div class="formitem">
					<div class="formitemtitle">SSO Client Cookie Timeout</div>
					<input class="text" id="sso_cookie_timeout" type="text" name="sso_cookie_timeout" value="<?php echo htmlspecialchars(isset($_REQUEST["cookie_timeout"]) ? (int)$_REQUEST["cookie_timeout"] : 0); ?>" />
					<div class="formitemdesc">How long the SSO Client cookie lives before it expires (in seconds).  A value of zero keeps the session and verification cookies until the browser is closed.  When not zero, this value may not be shorter than the SSO Server Session Timeout.</div>
				</div>
				<div class="formitem">
					<div class="formitemtitle">SSO Client Cookie Exit Timeout?</div>
					<select id="sso_cookie_exit_timeout" name="sso_cookie_exit_timeout">
						<option value="0">No</option>
						<option value="1">Yes</option>
					</select>
					<div class="formitemdesc">When enabled and SSO Client Cookie Timeout is non-zero, the session cookie will also expire in addition to the verification cookie when the browser is closed, whichever comes first.  When this option is set to 'No', active sessions are able to be cleanly logged out of if the previously closed browser is reopened and visits the application again before the session expires on the server.</div>
				</div>
				<div class="formitem">
					<div class="formitemtitle">SSO Client Cookie Validation Check</div>
					<input class="text" id="sso_cookie_check" type="text" name="sso_cookie_check" value="300" />
					<div class="formitemdesc">How long the SSO Client cookie data is valid for, in seconds, before the client needs to check with the SSO Server again.</div>
				</div>
			</div>
			<br />

			<div id="baseoptstestwrap" class="testresult">
				<div id="baseoptstest"></div>
			</div>
			<br />

			<script type="text/javascript">
			function RefreshBaseOptsTest()
			{
				$('#baseoptstestwrap').fadeIn('slow');
				$('#baseoptstest').load('install.php', {
					'action' : 'baseoptstest',
					'url' : $('#sso_server_endpoint_url').val(),
					'apikey' : $('#sso_server_apikey').val(),
					'secretkey' : $('#sso_server_secretkey').val(),
					'server_timeout' : $('#sso_server_session_timeout').val(),
					'cookie_name' : $('#sso_cookie_name').val(),
					'cookie_path' : $('#sso_cookie_path').val(),
					'cookie_timeout' : $('#sso_cookie_timeout').val(),
					'cookie_exit_timeout' : $('#sso_cookie_exit_timeout').val(),
					'cookie_check' : $('#sso_cookie_check').val(),

					'default_lang' : $('#sso_default_lang').val(),
					'sso_proxy_url' : $('#sso_proxy_url').val(),
					'sso_proxy_connect' : $('#sso_proxy_connect').val(),
					'sso_proxy_x_forwarded_for' : $('#sso_proxy_x_forwarded_for').val(),
					'sso_proxy_client_ip' : $('#sso_proxy_client_ip').val()
				});
			}

			$(function() {
				$('#sso_server_endpoint_url, #sso_server_apikey, #sso_server_secretkey, #sso_server_session_timeout, #sso_cookie_name, #sso_cookie_path, #sso_cookie_timeout, #sso_cookie_exit_timeout, #sso_cookie_check').keydown(RefreshBaseOptsTest).keyup(RefreshBaseOptsTest).change(RefreshBaseOptsTest);

				$('#sso_default_lang, #sso_proxy_url, #sso_proxy_connect, #sso_proxy_x_forwarded_for, #sso_proxy_client_ip').keydown(RefreshBaseOptsTest).keyup(RefreshBaseOptsTest).change(RefreshBaseOptsTest);
			});
			</script>

			<a href="#" onclick="RefreshBaseOptsTest();  return false;">Test the options</a><br /><br />
		</div>

		<div class="boxbuttons">
			<a href="#" onclick="return Page(4, 3);">&laquo; Prev</a> | <a href="#" onclick="return Page(4, 5);">Next &raquo;</a>
		</div>
	</div>

	<div id="page5" class="box" style="display: none;">
		<h1>Single Sign-On Client Setup</h1>
		<h3>Set up Single Sign-On (SSO) Client advanced options.</h3>
		<div class="boxmain">
			Set up the Single Sign-On (SSO) Client advanced options.<br /><br />

			<div class="formfields">
				<div class="formitem">
					<div class="formitemtitle">SSO Client Cookie over SSL only?</div>
					<select id="sso_cookie_ssl_only" name="sso_cookie_ssl_only">
						<option value="0">No</option>
						<option value="1">Yes</option>
					</select>
					<div class="formitemdesc">When enabled, the session information will only be sent over SSL connections.  Only enable this if the entire application uses SSL.</div>
				</div>
				<div class="formitem">
					<div class="formitemtitle">SSO Client Cookie Resets on IP Address Changes?</div>
					<select id="sso_cookie_reset_ipaddr_changes" name="sso_cookie_reset_ipaddr_changes">
						<option value="0">No</option>
						<option value="1">Yes</option>
					</select>
					<div class="formitemdesc">When enabled, the session information will be reset and the user forced to sign in again if their IP address changes.</div>
				</div>
				<div class="formitem">
					<div class="formitemtitle">SSO Client Cookie Symmetric Cipher</div>
					<select id="sso_cookie_cipher" name="sso_cookie_cipher">
						<option value="blowfish">Blowfish</option>
						<option value="aes256">AES-256</option>
					</select>
					<div class="formitemdesc">The cipher to use for encrypted cookie storage.  The ordering of the ciphers is intentional.  Blowfish is preferred, having withstood two decades of cryptanalysis.</div>
				</div>
				<div class="formitem">
					<div class="formitemtitle">Use SSO Client Cookie Dual Encryption</div>
					<select id="sso_cookie_dual_encrypt" name="sso_cookie_dual_encrypt">
						<option value="1">Yes</option>
						<option value="0">No</option>
					</select>
					<div class="formitemdesc">Two keys and two IVs are used to encrypt data twice with the same cipher as per <a href="http://cubicspot.blogspot.com/2013/02/extending-block-size-of-any-symmetric.html" target="_blank">this post</a>.</div>
				</div>
				<div class="formitem">
					<div class="formitemtitle">SSO Client Database Symmetric Cipher</div>
					<select id="sso_db_cipher" name="sso_db_cipher">
						<option value="blowfish">Blowfish</option>
						<option value="aes256">AES-256</option>
					</select>
					<div class="formitemdesc">The cipher to use for encrypted database storage.  The ordering of the ciphers is intentional.</div>
				</div>
				<div class="formitem">
					<div class="formitemtitle">Use SSO Client Database Dual Encryption</div>
					<select id="sso_db_dual_encrypt" name="sso_db_dual_encrypt">
						<option value="1">Yes</option>
						<option value="0">No</option>
					</select>
					<div class="formitemdesc">Two keys and two IVs are used to encrypt data twice with the same cipher.</div>
				</div>
				<div class="formitem">
					<div class="formitemtitle">SSO Client Accepts Site Admin?</div>
					<select id="sso_accept_site_admin" name="sso_accept_site_admin">
						<option value="1">Yes</option>
						<option value="0">No</option>
					</select>
					<div class="formitemdesc">When enabled, the SSO client will return true for SSO_IsSiteAdmin() when a signed in site admin visits.</div>
				</div>
				<div class="formitem">
					<div class="formitemtitle">SSO Client Checks Site Admin?</div>
					<select id="sso_check_site_admin" name="sso_check_site_admin">
						<option value="0">No</option>
						<option value="1">Yes</option>
					</select>
					<div class="formitemdesc">When enabled, the SSO client will always check with the SSO server whenever a signed in site admin visits.</div>
				</div>
				<div class="formitem">
					<div class="formitemtitle">SSO Client Default Language</div>
					<input class="text" id="sso_default_lang" type="text" name="sso_default_lang" value="<?php echo htmlspecialchars(isset($_REQUEST["default_lang"]) ? $_REQUEST["default_lang"] : ""); ?>" />
					<div class="formitemdesc">The IANA language code of an installed language pack to use as the default language.</div>
				</div>
				<div class="formitem">
					<div class="formitemtitle">Trusted 'X-Forwarded-For' Proxies</div>
					<input class="text" id="sso_proxy_x_forwarded_for" type="text" name="sso_proxy_x_forwarded_for" value="" />
					<div class="formitemdesc">A semi-colon separated list of IP addresses of trusted proxy servers that put the remote address into a 'X-Forwarded-For' HTTP header.  This is used to determine the originating IP address of the request if your application uses a proxy.</div>
				</div>
				<div class="formitem">
					<div class="formitemtitle">Trusted 'Client-IP' Proxies</div>
					<input class="text" id="sso_proxy_client_ip" type="text" name="sso_proxy_client_ip" value="" />
					<div class="formitemdesc">A semi-colon separated list of IP addresses of trusted proxy servers that put the remote address into a 'Client-IP' HTTP header.  This is used to determine the originating IP address of the request if your application uses a proxy.</div>
				</div>
				<div class="formitem">
					<div class="formitemtitle">HTTP Proxy URL</div>
					<input class="text" id="sso_proxy_url" type="text" name="sso_proxy_url" value="" />
					<div class="formitemdesc">An optional URL of a HTTP proxy server the client should use when communicating with the SSO server endpoint.</div>
				</div>
				<div class="formitem">
					<div class="formitemtitle">Use HTTP Proxy CONNECT?</div>
					<select id="sso_proxy_connect" name="sso_proxy_connect">
						<option value="0">No</option>
						<option value="1">Yes</option>
					</select>
					<div class="formitemdesc">When 'HTTP Proxy URL' is specified, this specifies the use of the HTTP CONNECT tunneling option.  Not all proxy servers support/enable this feature.</div>
				</div>
			</div>
		</div>

		<div class="boxbuttons">
			<a href="#" onclick="return Page(5, 4);">&laquo; Prev</a> | <a href="#" onclick="return Page(5, 6);">Next &raquo;</a>
		</div>
	</div>

	<div id="page6" class="box" style="display: none;">
		<h1>Ready To Install</h1>
		<h3>Ready to install Single Sign-On Client.</h3>
		<div class="boxmain">
			Single Sign-On Client is ready to install.  Click the link below to complete the installation process.
			Upon successful completion, 'install.php' (this installer) will be disabled.
			NOTE:  Be patient during the installation process.  It takes 5 to 30 seconds to complete.<br /><br />

			<div id="installwrap" class="testresult">
				<div id="install"></div>
			</div>
			<br />

			<script type="text/javascript">
			function Install()
			{
				$('#installlink').hide();
				$('.boxbuttons').hide();
				$('#installwrap').fadeIn('slow');
				$('#install').load('install.php', $('#installform').serialize() + '&rnd_' + Math.floor(Math.random() * 1000000));

				return false;
			}

			function InstallFailed()
			{
				$('#installlink').fadeIn('slow');
				$('.boxbuttons').fadeIn('slow');
			}
			</script>

			<a id="installlink" href="#" onclick="return Install();">Install Single Sign-On Client</a><br /><br />
		</div>

		<div class="boxbuttons">
			<a href="#" onclick="return Page(6, 5);">&laquo; Prev</a>
		</div>
	</div>

</div>
</form>
</body>
</html>
<?php
	}
?>