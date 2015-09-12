<?php
	// SSO client support class.
	// (C) 2015 CubicleSoft.  All Rights Reserved.

	// Drop-in replacement for hash_hmac() on hosts where Hash is not available.
	// Only supports HMAC-MD5 and HMAC-SHA1.
	if (!function_exists("hash_hmac"))
	{
		function hash_hmac($algo, $data, $key, $raw_output = false)
		{
			$algo = strtolower($algo);
			$size = 64;
			$opad = str_repeat("\x5C", $size);
			$ipad = str_repeat("\x36", $size);

			if (strlen($key) > $size)  $key = $algo($key, true);
			$key = str_pad($key, $size, "\x00");

			$y = strlen($key) - 1;
			for ($x = 0; $x < $y; $x++)
			{
				$opad[$x] = $opad[$x] ^ $key[$x];
				$ipad[$x] = $ipad[$x] ^ $key[$x];
			}

			$result = $algo($opad . $algo($ipad . $data, true), $raw_output);

			return $result;
		}
	}

	// Basic functionality.  Prefer to use SSO_Client wherever possible.
	class SSO_Client_Base
	{
		protected $rng, $ipaddr, $request, $cookie_sent, $getrequesthost_cache, $client_lang, $client_def_lang, $user_info, $user_cache, $removekeys, $orig_vars;
		public static $langmap;

		public function SendRequest($action, $options = array(), $endpoint = SSO_SERVER_ENDPOINT_URL, $apikey = SSO_SERVER_APIKEY, $secretkey = SSO_SERVER_SECRETKEY)
		{
			require_once SSO_CLIENT_ROOT_PATH . "/" . SSO_CLIENT_SUPPORT_PATH . "/sso_http.php";

			$options2 = array(
				"headers" => array(
					"User-Agent" => SSO_HTTP::GetUserAgent("Firefox"),
					"Accept" => "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
					"Accept-Language" => "en-us,en;q=0.5",
					"Accept-Charset" => "ISO-8859-1,utf-8;q=0.7,*;q=0.7",
					"Cache-Control" => "max-age=0"
				)
			);
			if (defined("SSO_DEBUG") && SSO_DEBUG)  $options2["debug"] = true;

			if (defined("SSO_CLIENT_PROXY_URL") && defined("SSO_CLIENT_PROXY_CONNECT") && SSO_CLIENT_PROXY_URL != "")
			{
				$options2["proxyurl"] = SSO_CLIENT_PROXY_URL;
				$options2["proxyconnect"] = SSO_CLIENT_PROXY_CONNECT;
			}

			if (!is_array($this->ipaddr))  $this->ipaddr = self::GetRemoteIP();

			$url = $endpoint;
			$url .= (strpos($endpoint, "?") === false ? "?" : "&");
			$url .= "apikey=" . urlencode($apikey);
			$url .= "&action=" . urlencode($action);
			$url .= "&ipaddr=" . urlencode($this->ipaddr["ipv6"]);
			$url .= "&ver=3.0";

			// Create encrypted data packet.
			$options["apikey"] = $apikey;
			$options["action"] = $action;
			$options["ver"] = "3.0";
			$options["ts"] = gmdate("Y-m-d H:i:s", time());
			$data = json_encode($options);
			unset($options);
			$cryptopts = array("mode" => "CBC");
			if (strpos($secretkey, ":") === false)
			{
				$mode = "bf";
				$key = pack("H*", substr($secretkey, 0, -16));
				$cryptopts["iv"] = pack("H*", substr($secretkey, -16));
			}
			else
			{
				$info = explode(":", $secretkey);
				if (count($info) < 3)  return array("success" => false, "error" => $this->Translate("Invalid secret key."));

				$mode = $info[0];
				$key = pack("H*", $info[1]);
				$cryptopts["iv"] = pack("H*", $info[2]);

				if (count($info) >= 5)
				{
					$cryptopts["key2"] = pack("H*", $info[3]);
					$cryptopts["iv2"] = pack("H*", $info[4]);
				}

				unset($info);
			}
			if (!isset($this->rng))  $this->rng = new SSO_CSPRNG();
			$cryptopts["prefix"] = pack("H*", $this->rng->GenerateToken());

			if ($mode === "aes256")  $data = SSO_ExtendedAES::CreateDataPacket($data, $key, $cryptopts);
			else  $data = SSO_Blowfish::CreateDataPacket($data, $key, $cryptopts);

			$data = str_replace(array("+", "/", "="), array("-", "_", ""), base64_encode($data));

			$options2["postvars"] = array("data" => $data);

			// Send the request.
			$retries = 0;
			do
			{
				$result = SSO_HTTP::RetrieveWebpage($url, $options2);

				$retries++;
			} while (!$result["success"] && $retries < 3);

			if (!$result["success"])  return $result;

			// Decode and extract response.
			if ($result["body"]{0} == "{")  $data = @json_decode(trim($result["body"]), true);
			else
			{
				$data = @base64_decode(trim($result["body"]));

				if ($data !== false)
				{
					if ($mode === "aes256")  $data = SSO_ExtendedAES::ExtractDataPacket($data, $key, $cryptopts);
					else  $data = SSO_Blowfish::ExtractDataPacket($data, $key, $cryptopts);
				}

				if ($data !== false)  $data = @json_decode($data, true);
			}

			if (is_array($data))  $result = $data;
			else  $result = array("success" => false, "error" => "Unable to decode response data from the server.", "info" => $result["body"]);

			if (!$result["success"])  $result["error"] = $this->Translate($result["error"]);

			return $result;
		}

		public static function GetRemoteIP()
		{
			require_once SSO_CLIENT_ROOT_PATH . "/" . SSO_CLIENT_SUPPORT_PATH . "/sso_ipaddr.php";

			$proxies = array();
			$ipaddrs = explode(";", SSO_CLIENT_PROXY_X_FORWARDED_FOR);
			foreach ($ipaddrs as $ipaddr)
			{
				$ipaddr = trim($ipaddr);
				if ($ipaddr != "")  $proxies[$ipaddr] = "xforward";
			}
			$ipaddrs = explode(";", SSO_CLIENT_PROXY_CLIENT_IP);
			foreach ($ipaddrs as $ipaddr)
			{
				$ipaddr = trim($ipaddr);
				if ($ipaddr != "")  $proxies[$ipaddr] = "clientip";
			}

			return SSO_IPAddr::GetRemoteIP($proxies);
		}

		protected function ProcPOSTStr($data)
		{
			$data = trim($data);
			if (get_magic_quotes_gpc())  $data = stripslashes($data);

			return $data;
		}

		protected function ProcessSingleInput($data)
		{
			if (!is_array($data))  return;
			foreach ($data as $key => $val)
			{
				if (is_string($val))  $this->request[$key] = $this->ProcPOSTStr($val);
				else if (is_array($val))
				{
					$this->request[$key] = array();
					foreach ($val as $key2 => $val2)  $this->request[$key][$key2] = $this->ProcPOSTStr($val2);
				}
				else  $this->request[$key] = $val;
			}
		}

		// Cleans up all PHP input issues so that $_REQUEST may be used as expected.
		protected function ProcessAllInput()
		{
			$this->request = $_REQUEST;

			$this->ProcessSingleInput($_COOKIE);
			$this->ProcessSingleInput($_GET);
			$this->ProcessSingleInput($_POST);

			return $this->request;
		}

		// Swiped from CubicleSoft PHP HTTP cookie functions.
		public function SetCookieFixDomain($name, $value = "", $expires = 0, $path = "", $domain = "", $secure = false, $httponly = false)
		{
			if (headers_sent())
			{
				echo htmlspecialchars($this->Translate("SSO client unable to set cookie '%s'.  Error:  Headers already sent.  This means HTML or other data (e.g. UTF-8 byte order marker) has been output, which caused HTTP headers to be sent prematurely.  Contact the system/website administrator to correct this issue.", $name));
				exit();
			}

			if (!empty($domain))
			{
				// Fix the domain to accept domains with and without 'www.'.
				if (strtolower(substr($domain, 0, 4)) == "www.")  $domain = substr($domain, 4);
				if (strpos($domain, ".") === false)  $domain = "";
				else  $domain = "." . $domain;

				// Remove port information.
				$port = strpos($domain, ":");
				if ($port !== false)  $domain = substr($domain, 0, $port);
			}

			header('Set-Cookie: ' . rawurlencode($name) . "=" . rawurlencode($value)
								. (empty($expires) ? "" : "; expires=" . gmdate("D, d-M-Y H:i:s", $expires) . " GMT")
								. (empty($path) ? "" : "; path=" . $path)
								. (empty($domain) ? "" : "; domain=" . $domain)
								. (!$secure ? "" : "; secure")
								. (!$httponly ? "" : "; HttpOnly"), false);

			$_COOKIE[$name] = $value;
			$_REQUEST[$name] = $value;
			unset($_GET[$name]);
			unset($_POST[$name]);
			$this->request[$name] = $value;

			// Stop proxies and browsers from caching the current URL.
			if (!$this->cookie_sent)
			{
				header("Cache-Control: no-cache, no-store, max-age=0");
				header("Pragma: no-cache");
				header("Expires: -1");

				$this->cookie_sent = true;
			}
		}

		// Swiped from Barebones CMS support functions.
		public static function IsSSLRequest()
		{
			return ((isset($_SERVER["HTTPS"]) && ($_SERVER["HTTPS"] == "on" || $_SERVER["HTTPS"] == "1")) || (isset($_SERVER["SERVER_PORT"]) && $_SERVER["SERVER_PORT"] == "443") || (str_replace("\\", "/", strtolower(substr($_SERVER["REQUEST_URI"], 0, 8))) == "https://"));
		}

		// Returns 'http[s]://www.something.com[:port]' based on the current page request.
		public function GetRequestHost($protocol = "")
		{
			$protocol = strtolower($protocol);
			$ssl = ($protocol == "https" || ($protocol == "" && self::IsSSLRequest()));
			if ($protocol == "")  $type = "def";
			else if ($ssl)  $type = "https";
			else  $type = "http";

			if (!isset($this->getrequesthost_cache))  $this->getrequesthost_cache = array();
			if (isset($this->getrequesthost_cache[$type]))  return $this->getrequesthost_cache[$type];

			$url = "http" . ($ssl ? "s" : "") . "://";
			if ($ssl && defined("HTTPS_SERVER") && HTTPS_SERVER != "")  $url .= HTTPS_SERVER;
			else if (!$ssl && defined("HTTP_SERVER") && HTTP_SERVER != "")  $url .= HTTP_SERVER;
			else
			{
				$str = str_replace("\\", "/", $_SERVER["REQUEST_URI"]);
				$pos = strpos($str, "?");
				if ($pos !== false)  $str = substr($str, 0, $pos);
				$str2 = strtolower($str);
				if (substr($str2, 0, 7) == "http://")
				{
					$pos = strpos($str, "/", 7);
					if ($pos === false)  $str = "";
					else  $str = substr($str, 7, $pos);
				}
				else if (substr($str2, 0, 8) == "https://")
				{
					$pos = strpos($str, "/", 8);
					if ($pos === false)  $str = "";
					else  $str = substr($str, 8, $pos);
				}
				else  $str = "";

				if ($str != "")  $host = $str;
				else if (isset($_SERVER["HTTP_HOST"]))  $host = $_SERVER["HTTP_HOST"];
				else  $host = $_SERVER["SERVER_NAME"] . ":" . (int)$_SERVER["SERVER_PORT"];

				$pos = strpos($host, ":");
				if ($pos === false)  $port = 0;
				else
				{
					$port = (int)substr($host, $pos + 1);
					$host = substr($host, 0, $pos);
				}
				if ($port < 1 || $port > 65535)  $port = ($ssl ? 443 : 80);
				$url .= preg_replace('/[^a-z0-9.\-]/', "", strtolower($host));
				if ($protocol == "" && ((!$ssl && $port != 80) || ($ssl && $port != 443)))  $url .= ":" . $port;
				else if ($protocol == "http" && !$ssl && $port != 80)  $url .= ":" . $port;
				else if ($protocol == "https" && $ssl && $port != 443)  $url .= ":" . $port;
			}

			$this->getrequesthost_cache[$type] = $url;

			return $url;
		}

		public static function GetRequestURLBase()
		{
			$str = str_replace("\\", "/", $_SERVER["REQUEST_URI"]);
			$pos = strpos($str, "?");
			if ($pos !== false)  $str = substr($str, 0, $pos);
			$str2 = strtolower($str);
			if (substr($str2, 0, 7) == "http://" || substr($str2, 0, 8) == "https://")
			{
				$pos = strpos($str, "/", 8);
				if ($pos === false)  $str = "/";
				else  $str = substr($str, $pos);
			}

			return $str;
		}

		public function GetFullRequestURLBase($protocol = "")
		{
			return $this->GetRequestHost($protocol) . self::GetRequestURLBase();
		}

		protected function Translate()
		{
			$args = func_get_args();
			if (!count($args) || $args[0] == "")  return "";
			if (isset($this->client_lang) && isset($this->client_def_lang) && isset(self::$langmap))
			{
				$arg = $args[0];
				if (isset(self::$langmap[$this->client_lang]) && isset(self::$langmap[$this->client_lang][$arg]))  $args[0] = self::$langmap[$this->client_lang][$arg];
				else if (isset(self::$langmap[$this->client_def_lang]) && isset(self::$langmap[$this->client_def_lang][$arg]))  $args[0] = self::$langmap[$this->client_def_lang][$arg];
				else if (isset(self::$langmap[""][$arg]))  $args[0] = self::$langmap[""][$arg];
				else if (function_exists("SSO_Untranslated"))  SSO_Untranslated($args);
			}

			return call_user_func_array("sprintf", $args);
		}

		protected function PostTranslate($str)
		{
			if (isset($this->client_lang) && isset($this->client_def_lang) && isset(self::$langmap))
			{
				if (isset(self::$langmap[$this->client_lang]) && isset(self::$langmap[$this->client_lang][""]) && is_array(self::$langmap[$this->client_lang][""]))  $str = str_replace(self::$langmap[$this->client_lang][""][0], self::$langmap[$this->client_lang][""][1], $str);
				else if (isset(self::$langmap[$this->client_def_lang]) && isset(self::$langmap[$this->client_def_lang][""]) && is_array(self::$langmap[$this->client_def_lang][""]))  $str = str_replace(self::$langmap[$this->client_def_lang][""][0], self::$langmap[$this->client_def_lang][""][1], $str);
				else if (isset(self::$langmap[""][""]) && is_array(self::$langmap[""][""]))  $str = str_replace(self::$langmap[""][""][0], self::$langmap[""][""][1], $str);
			}

			return $str;
		}

		public function SetLanguage($path, $lang)
		{
			$lang = preg_replace('/\s+/', "_", trim(preg_replace('/[^a-z]/', " ", strtolower($lang))));
			if ($lang == "")
			{
				$path .= "default/";
			}
			else
			{
				if ($lang == "default")  return array("success" => false, "error" => "Invalid language.");
				$path .= $lang . "/";
			}

			if (isset(self::$langmap[$lang]))
			{
				if ($lang != "")  $this->client_lang = $lang;

				return array("success" => true);
			}
			self::$langmap[$lang] = array();

			$dir = @opendir($path);
			if ($dir === false)  return array("success" => false, "error" => "Directory does not exist.", "info" => $path);

			while (($file = readdir($dir)) !== false)
			{
				if (strtolower(substr($file, -4)) == ".php")  require_once $path . $file;
			}

			closedir($dir);

			if (isset(self::$langmap[$lang][""]) && is_array(self::$langmap[$lang][""]))  self::$langmap[$lang][""] = array(array_keys(self::$langmap[$lang][""]), array_values(self::$langmap[$lang][""]));

			$this->client_lang = $lang;

			return array("success" => true);
		}

		protected function InitLangmap($path, $default = "")
		{
			self::$langmap = array();
			$this->SetLanguage($path, "");
			if ($default != "")  $this->SetLanguage($path, $default);
			$this->client_def_lang = $this->client_lang;
			if (isset($_SERVER["HTTP_ACCEPT_LANGUAGE"]))
			{
				$langs = explode(",", $_SERVER["HTTP_ACCEPT_LANGUAGE"]);
				foreach ($langs as $lang)
				{
					$lang = trim($lang);
					$pos = strpos($lang, ";");
					if ($pos !== false)  $lang = substr($lang, 0, $pos);
					if ($lang != "")
					{
						$result = $this->SetLanguage($path, $lang);
						if ($result["success"])  break;
					}
				}
			}
		}

		protected function ProcessLogin($info, $fromserver = false)
		{
			$this->user_info = $info;
			unset($this->user_info["success"]);
			unset($this->user_info["rinfo"]);
			$this->user_info["loaded"] = true;

			$this->user_cache = array(
				"fromserver" => $fromserver,
				"changed" => true,
				"dbchanged" => true,
				"hasdb" => false,
				"ts" => gmdate("Y-m-d H:i:s", time() + SSO_COOKIE_CHECK),
				"ts2" => time() + SSO_COOKIE_CHECK,
				"ipaddr" => ($this->ipaddr["ipv4"] != "" && strlen($this->ipaddr["ipv4"]) < strlen($this->ipaddr["shortipv6"]) ? $this->ipaddr["ipv4"] : $this->ipaddr["shortipv6"]),
				"data" => array(),
				"dbdata" => array()
			);

			unset($_COOKIE[SSO_COOKIE_NAME . "_c"]);
			unset($_COOKIE[SSO_COOKIE_NAME . "_s"]);
			unset($_COOKIE[SSO_COOKIE_NAME . "_v"]);

			if (isset($info["rinfo"]))
			{
				$data = @base64_decode($info["rinfo"]);
				if ($data !== false)  $data = SSO_Blowfish::ExtractDataPacket($data, pack("H*", SSO_CLIENT_RAND_SEED7), array("mode" => "CBC", "iv" => pack("H*", SSO_CLIENT_RAND_SEED8), "key2" => pack("H*", SSO_CLIENT_RAND_SEED9), "iv2" => pack("H*", SSO_CLIENT_RAND_SEED10)));
				if ($data !== false && function_exists("gzcompress") && function_exists("gzuncompress"))  $data = @gzuncompress($data);
				if ($data !== false)  $data = @unserialize($data);

				if ($data !== false)
				{
					// Reload.
					$_SERVER = $data["server"];
					$_GET = $data["get"];
					$_POST = $data["post"];
					$_REQUEST = $data["request"];
					$_FILES = $data["files"];

					// Initialize language settings.
					$this->InitLangmap(SSO_CLIENT_ROOT_PATH . "/" . SSO_CLIENT_LANG_PATH . "/", SSO_CLIENT_DEFAULT_LANG);

					// Initialize IP address for API calls.
					$this->ipaddr = self::GetRemoteIP();
				}
			}

			// Reinitialize stored input.
			unset($_GET[SSO_COOKIE_NAME . "_c"]);
			unset($_GET[SSO_COOKIE_NAME . "_s"]);
			unset($_GET[SSO_COOKIE_NAME . "_v"]);
			unset($_POST[SSO_COOKIE_NAME . "_c"]);
			unset($_POST[SSO_COOKIE_NAME . "_s"]);
			unset($_POST[SSO_COOKIE_NAME . "_v"]);

			// Initialize internal input variables.
			$this->ProcessAllInput();
		}

		// Perform redirection to current URL minus specified parameters.
		protected function SafeRedirect($removekeys)
		{
			if (isset($this->removekeys))  $removekeys = array_merge($removekeys, $this->removekeys);

			$url = $this->GetFullRequestURLBase();
			if (isset($_SERVER["QUERY_STRING"]))
			{
				$qstr = explode("&", $_SERVER["QUERY_STRING"]);
				foreach ($qstr as $num => $opt)
				{
					foreach ($removekeys as $key)
					{
						$key .= "=";
						if (substr($opt, 0, strlen($key)) == $key)  unset($qstr[$num]);
					}
				}
				$qstr = implode("&", $qstr);
				if ($qstr != "")  $url .= "?" . $qstr;
			}

			header("Location: " . $url);
			exit();
		}

		public function LoggedIn()
		{
			if (isset($this->user_info))  return ($this->user_info["sso_id"] != "");
			if (!isset($this->request[SSO_COOKIE_NAME . "_s"]))  return false;

			// Decrypt the cookie.
			$this->user_info = array("sso_id" => "");
			$cdata = (string)$this->request[SSO_COOKIE_NAME . "_s"];
			$cdata = @base64_decode(str_replace(array("-", "_"), array("+", "/"), $cdata));
			if ($cdata === false)  return false;

			$mode = (SSO_COOKIE_CIPHER == "aes256" ? "aes256" : "blowfish");
			$key = pack("H*", SSO_CLIENT_RAND_SEED);
			$options = array("mode" => "CBC", "iv" => pack("H*", SSO_CLIENT_RAND_SEED2), "lightweight" => true);
			if (SSO_COOKIE_DUAL_ENCRYPT)
			{
				$options["key2"] = pack("H*", SSO_CLIENT_RAND_SEED4);
				$options["iv2"] = pack("H*", SSO_CLIENT_RAND_SEED5);
			}

			if ($mode == "aes256")  $cdata = SSO_ExtendedAES::ExtractDataPacket($cdata, $key, $options);
			else  $cdata = SSO_Blowfish::ExtractDataPacket($cdata, $key, $options);

			if ($cdata === false)  return false;
			$vdata = hash_hmac("sha1", $cdata . ":" . SSO_SERVER_APIKEY, pack("H*", SSO_CLIENT_RAND_SEED6), true);
			$compressed = (bool)(int)substr($cdata, 0, 1);
			$cdata = substr($cdata, 2);
			if ($compressed)  $cdata = @gzuncompress($cdata);
			if ($cdata === false)  return false;
			$cdata = @json_decode($cdata, true);
			if ($cdata === false)  return false;

			// Load the user information structure.
			$this->user_info = array(
				"loaded" => false,
				"sso_id" => $cdata["s"],
				"id" => $cdata["i"],
				"extra" => $cdata["e"],
				"field_map" => array(),
				"writable" => array(),
				"tag_map" => (isset($cdata["t"]) ? $cdata["t"] : array()),
				"admin" => (isset($cdata["a"]) ? (bool)$cdata["a"] : false)
			);
			foreach ($this->user_info["tag_map"] as $key => $val)  $this->user_info["tag_map"][$key] = true;
			$this->user_cache = array(
				"fromserver" => false,
				"changed" => false,
				"dbchanged" => false,
				"hasdb" => (isset($cdata["b"]) ? (bool)$cdata["b"] : false),
				"ts" => $cdata["c"],
				"ipaddr" => ($this->ipaddr["ipv4"] != "" && strlen($this->ipaddr["ipv4"]) < strlen($this->ipaddr["shortipv6"]) ? $this->ipaddr["ipv4"] : $this->ipaddr["shortipv6"]),
				"data" => (isset($cdata["d"]) ? $cdata["d"] : array()),
				"dbdata" => array()
			);

			// If the verification cookie is missing or invalid, logout of the session.
			if (isset($this->request[SSO_COOKIE_NAME . "_v"]))  $vdata2 = @base64_decode(str_replace(array("-", "_"), array("+", "/"), (string)$this->request[SSO_COOKIE_NAME . "_v"]));
			else  $vdata2 = false;
			if ($vdata2 === false || $vdata !== $vdata2)
			{
				$this->Logout();

				return false;
			}

			// Check for outdated login information.
			$ts = $this->user_cache["ts"];
			$this->user_cache["ts2"] = gmmktime((int)substr($ts, 11, 2), (int)substr($ts, 14, 2), (int)substr($ts, 17, 2), (int)substr($ts, 5, 2), (int)substr($ts, 8, 2), (int)substr($ts, 0, 4));
			if (!isset($this->request[SSO_COOKIE_NAME . "_c"]) || $this->user_cache["ts2"] < time() || $this->user_cache["ipaddr"] != $cdata["p"] || ($this->IsSiteAdmin() && defined("SSO_CLIENT_CHECK_SITE_ADMIN") && SSO_CLIENT_CHECK_SITE_ADMIN))
			{
				// Reset the session if the IP address changed.
				if (defined("SSO_COOKIE_RESET_IPADDR_CHANGES") && SSO_COOKIE_RESET_IPADDR_CHANGES && $this->user_cache["ipaddr"] != $cdata["p"])
				{
					$this->user_info["sso_id"] = "";

					return false;
				}

				// Validate the login.  Handle scenarios where the SSO Server is unavailable.
				$options = array(
					"sso_id" => $this->user_info["sso_id"],
					"expires" => (SSO_COOKIE_TIMEOUT > 0 && SSO_COOKIE_TIMEOUT < SSO_SERVER_SESSION_TIMEOUT ? SSO_COOKIE_TIMEOUT : SSO_SERVER_SESSION_TIMEOUT)
				);

				$result = $this->SendRequest("getlogin", $options);
				if (!$result["success"] && !isset($result["info"]))
				{
					$this->user_info["sso_id"] = "";

					return false;
				}
				if ($result["success"])  $this->ProcessLogin($result);
			}

			return true;
		}

		public function FromSSOServer()
		{
			return $this->user_cache["fromserver"];
		}

		public function CanAutoLogin()
		{
			if (!isset($_COOKIE["sso_server_ns2"]))  return false;

			// Only the server can decrypt the namespace cookie.  Pass it along to the endpoint and get the response.
			$options = array(
				"ns" => $_COOKIE["sso_server_ns2"]
			);

			$result = $this->SendRequest("canautologin", $options);
			if (!$result["success"])  return false;

			return true;
		}

		// Self-contained initialization.
		public function Init($removekeys = array())
		{
			$this->rng = new SSO_CSPRNG();

			// Initialize internal input variables.
			$this->ProcessAllInput();
			$this->cookie_sent = false;

			// Initialize language settings.
			$this->InitLangmap(SSO_CLIENT_ROOT_PATH . "/" . SSO_CLIENT_LANG_PATH . "/", SSO_CLIENT_DEFAULT_LANG);

			// Initialize IP address for API calls.
			$this->ipaddr = self::GetRemoteIP();

			// Redirect the browser to a similar URL.
			if (isset($this->request["from_sso_server"]) && isset($this->request["sso_id"]) && isset($this->request["sso_id2"]))
			{
				$this->SetCookieFixDomain(SSO_COOKIE_NAME . "_s_id", $this->request["sso_id"], 0, SSO_COOKIE_PATH, "", self::IsSSLRequest(), true);
				$this->SetCookieFixDomain(SSO_COOKIE_NAME . "_s_id2", $this->request["sso_id2"], 0, SSO_COOKIE_PATH, "", self::IsSSLRequest(), true);

				$this->SafeRedirect(array("sso_id", "sso_id2"));
			}

			// If the input request appears to be from the SSO server and a new session, process the new session.
			if (isset($this->request["from_sso_server"]) && isset($this->request[SSO_COOKIE_NAME . "_s_id"]) && isset($this->request[SSO_COOKIE_NAME . "_s_id2"]))
			{
				// Validate the login and get the original request data back.
				$options = array(
					"sso_id" => $this->request[SSO_COOKIE_NAME . "_s_id"],
					"sso_id2" => $this->request[SSO_COOKIE_NAME . "_s_id2"],
					"rid" => (isset($this->request[SSO_COOKIE_NAME . "_rid"]) ? $this->request[SSO_COOKIE_NAME . "_rid"] : ""),
					"expires" => (SSO_COOKIE_TIMEOUT > 0 && SSO_COOKIE_TIMEOUT < SSO_SERVER_SESSION_TIMEOUT ? SSO_COOKIE_TIMEOUT : SSO_SERVER_SESSION_TIMEOUT)
				);

				$result = $this->SendRequest("getlogin", $options);
				if ($result["success"])
				{
					// Process the login.
					$this->ProcessLogin($result, true);

					// Delete the old session.
					$options["delete_old"] = 1;
					$this->SendRequest("getlogin", $options);

					// Delete ID cookies.
					$this->SetCookieFixDomain(SSO_COOKIE_NAME . "_s_id", "", 1, SSO_COOKIE_PATH, "", self::IsSSLRequest(), true);
					$this->SetCookieFixDomain(SSO_COOKIE_NAME . "_s_id2", "", 1, SSO_COOKIE_PATH, "", self::IsSSLRequest(), true);

					// Delete the recovery cookie.
					$this->SetCookieFixDomain(SSO_COOKIE_NAME . "_rid", "", 1, SSO_COOKIE_PATH, "", self::IsSSLRequest(), true);
				}
			}

			// If the input request appears to be from the SSO server and a remote setlogin request, save the information for later.
			if (isset($this->request["from_sso_server"]) && isset($this->request["sso_setlogin_id"]) && isset($this->request["sso_setlogin_token"]))
			{
				$this->SetCookieFixDomain(SSO_COOKIE_NAME . "_sr_id", $this->request["sso_setlogin_id"], 0, SSO_COOKIE_PATH, "", self::IsSSLRequest(), true);
				$this->SetCookieFixDomain(SSO_COOKIE_NAME . "_sr_t", $this->request["sso_setlogin_token"], 0, SSO_COOKIE_PATH, "", self::IsSSLRequest(), true);

				$this->SafeRedirect(array("sso_setlogin_id", "sso_setlogin_token"));
			}

			$this->removekeys = $removekeys;
			if ($this->LoggedIn() && !$this->FromSSOServer())
			{
				foreach ($this->removekeys as $key)
				{
					if (isset($_GET[$key]))  $this->SafeRedirect(array());
				}
			}

			$this->orig_vars = array("server" => $_SERVER, "get" => $_GET, "post" => $_POST, "request" => $_REQUEST, "files" => $_FILES);
			unset($this->orig_vars["get"]["from_sso_server"]);
			unset($this->orig_vars["post"]["from_sso_server"]);
			unset($this->orig_vars["request"]["from_sso_server"]);
		}

		public function Login($lang = "", $msg = "", $extra = array(), $appurl = "")
		{
			if ($msg != "" || !$this->LoggedIn())
			{
				// Send current context, retrieve the login location from the SSO server, and redirect the user.
				$url = $this->GetFullRequestURLBase();
				if (isset($_SERVER["QUERY_STRING"]) && $_SERVER["QUERY_STRING"] != "")  $url .= "?" . $_SERVER["QUERY_STRING"];

				$data = serialize($this->orig_vars);
				if (function_exists("gzcompress") && function_exists("gzuncompress"))  $data = @gzcompress($data);
				$data = SSO_Blowfish::CreateDataPacket($data, pack("H*", SSO_CLIENT_RAND_SEED7), array("prefix" => pack("H*", $this->rng->GenerateToken()), "mode" => "CBC", "iv" => pack("H*", SSO_CLIENT_RAND_SEED8), "key2" => pack("H*", SSO_CLIENT_RAND_SEED9), "iv2" => pack("H*", SSO_CLIENT_RAND_SEED10)));

				if ($appurl == "")  $appurl = $this->GetRequestHost() . SSO_COOKIE_PATH;

				$options = array(
					"url" => $url,
					"info" => base64_encode($data),
					"files" => (count($_FILES) > 0 ? "1" : "0"),
					"lang" => $lang,
					"initmsg" => $msg,
					"extra" => $extra,
					"appurl" => $appurl
				);

				$result = $this->SendRequest("initlogin", $options);
				if (!$result["success"])
				{
					echo htmlspecialchars($this->Translate("Unable to obtain SSO server login access.  Error:  %s", $result["error"]));
					exit();
				}

				// Set the recovery ID to be able to retrieve the old data later.  Doubles as a XSRF defense.
				$this->SetCookieFixDomain(SSO_COOKIE_NAME . "_rid", $result["rid"], 0, SSO_COOKIE_PATH, "", self::IsSSLRequest(), true);

				header("Location: " . $result["url"]);
				exit();
			}
		}

		public function CanRemoteLogin()
		{
			return (isset($this->request[SSO_COOKIE_NAME . "_sr_id"]) && isset($this->request[SSO_COOKIE_NAME . "_sr_t"]));
		}

		public function RemoteLogin($userid, $fieldmap = array(), $endpoint = SSO_SERVER_ENDPOINT_URL, $apikey = SSO_SERVER_APIKEY, $secretkey = SSO_SERVER_SECRETKEY)
		{
			if (!$this->CanRemoteLogin())
			{
				echo htmlspecialchars($this->Translate("Unable to retrieve ID or token cookie for SSO server login."));
				exit();
			}

			$options = array(
				"sso_id" => $this->request[SSO_COOKIE_NAME . "_sr_id"],
				"token" => $this->request[SSO_COOKIE_NAME . "_sr_t"],
				"user_id" => $userid,
				"updateinfo" => @json_encode($fieldmap)
			);

			$result = $this->SendRequest("setlogin", $options, $endpoint, $apikey, $secretkey);
			if (!$result["success"])
			{
				echo htmlspecialchars($this->Translate("Unable to obtain SSO server remote login access.  Error:  %s", $result["error"]));
				exit();
			}

			// Delete the cookies.
			$this->SetCookieFixDomain(SSO_COOKIE_NAME . "_sr_id", "", 1, SSO_COOKIE_PATH, "", self::IsSSLRequest(), true);
			$this->SetCookieFixDomain(SSO_COOKIE_NAME . "_sr_t", "", 1, SSO_COOKIE_PATH, "", self::IsSSLRequest(), true);

			header("Location: " . $result["url"]);
			exit();
		}

		public function Logout()
		{
			if (isset($this->user_info) && isset($this->user_info["sso_id"]) && $this->user_info["sso_id"] != "")
			{
				$options = array(
					"sso_id" => $this->user_info["sso_id"]
				);

				$this->SendRequest("logout", $options);

				$this->user_info["sso_id"] = "";
			}

			$this->SetCookieFixDomain(SSO_COOKIE_NAME . "_c", "0", 1, SSO_COOKIE_PATH, "", SSO_COOKIE_SSL_ONLY);
			$this->SetCookieFixDomain(SSO_COOKIE_NAME . "_s", "", 1, SSO_COOKIE_PATH, "", SSO_COOKIE_SSL_ONLY, true);
			$this->SetCookieFixDomain(SSO_COOKIE_NAME . "_v", "", 1, SSO_COOKIE_PATH, "", SSO_COOKIE_SSL_ONLY, true);
		}

		public function HasDBData()
		{
			return $this->user_cache["hasdb"];
		}

		public function LoadDBData($data)
		{
			$options = array("mode" => "CBC");
			$data2 = explode(":", $data);
			if (count($data2) == 3)
			{
				$mode = ($data2[0] == "aes256" ? "aes256" : "blowfish");
				$key = pack("H*", SSO_CLIENT_RAND_SEED11);
				$options["iv"] = pack("H*", SSO_CLIENT_RAND_SEED12);
				if ((int)$data2[1] === 2)
				{
					$options["key2"] = pack("H*", SSO_CLIENT_RAND_SEED13);
					$options["iv2"] = pack("H*", SSO_CLIENT_RAND_SEED14);
				}
				$data = $data2[2];
			}
			else
			{
				$mode = "blowfish";
				$compressed = (function_exists("gzcompress") && function_exists("gzuncompress"));
				$key = pack("H*", SSO_CLIENT_RAND_SEED3);
				$options["iv"] = pack("H*", SSO_CLIENT_RAND_SEED2);
			}

			$data = @base64_decode($data);
			if ($data === false)  return false;

			if ($mode == "aes256")  $data = SSO_ExtendedAES::ExtractDataPacket($data, $key, $options);
			else  $data = SSO_Blowfish::ExtractDataPacket($data, $key, $options);

			if ($data === false)  return false;

			if (count($data2) != 3)  $compressed = false;
			else
			{
				$compressed = (bool)(int)substr($data, 0, 1);
				$data = substr($data, 2);
			}
			if ($compressed)  $data = @gzuncompress($data);
			if ($data === false)  return false;

			if (count($data2) == 3)  $data = @json_decode($data, true);
			else  $data = @unserialize($data);

			if ($data === false)  return false;

			$this->user_cache["dbdata"] = $data;

			return true;
		}

		public function SaveDBData()
		{
			$mode = (SSO_CLIENT_DB_CIPHER == "aes256" ? "aes256" : "blowfish");

			$data = @json_encode($this->user_cache["dbdata"]);
			if (function_exists("gzcompress") && function_exists("gzuncompress"))  $data = "1:" . @gzcompress($data);
			else  $data = "0:" . $data;

			$key = pack("H*", SSO_CLIENT_RAND_SEED11);
			$options = array("prefix" => pack("H*", $this->rng->GenerateToken()), "mode" => "CBC", "iv" => pack("H*", SSO_CLIENT_RAND_SEED12));
			if (SSO_CLIENT_DB_DUAL_ENCRYPT)
			{
				$options["key2"] = pack("H*", SSO_CLIENT_RAND_SEED13);
				$options["iv2"] = pack("H*", SSO_CLIENT_RAND_SEED14);
			}

			if ($mode == "aes256")  $data = SSO_ExtendedAES::CreateDataPacket($data, $key, $options);
			else  $data = SSO_Blowfish::CreateDataPacket($data, $key, $options);

			$data = $mode . ":" . (SSO_CLIENT_DB_DUAL_ENCRYPT ? "2" : "1") . ":" . base64_encode($data);

			return $data;
		}

		public function IsSiteAdmin()
		{
			return (!defined("SSO_CLIENT_ACCEPT_SITE_ADMIN") || SSO_CLIENT_ACCEPT_SITE_ADMIN ? $this->user_info["admin"] : false);
		}

		public function HasTag($name)
		{
			return isset($this->user_info["tag_map"][$name]);
		}

		public function LoadUserInfo($savefirst = false)
		{
			if (!isset($this->user_info))  return false;
			if (!$savefirst && $this->user_info["loaded"])  return true;

			$options = array(
				"sso_id" => $this->user_info["sso_id"],
				"expires" => (SSO_COOKIE_TIMEOUT > 0 && SSO_COOKIE_TIMEOUT < SSO_SERVER_SESSION_TIMEOUT ? SSO_COOKIE_TIMEOUT : SSO_SERVER_SESSION_TIMEOUT)
			);
			if ($savefirst)  $options["updateinfo"] = @json_encode($this->user_info["field_map"]);

			$result = $this->SendRequest("getlogin", $options);
			if (!$result["success"] && !isset($result["info"]))  return false;
			if ($result["success"])  $this->ProcessLogin($result);

			return $this->user_info["loaded"];
		}

		public function UserLoaded()
		{
			return $this->user_info["loaded"];
		}

		public function GetField($key, $default = false)
		{
			return (isset($this->user_info["field_map"][$key]) ? $this->user_info["field_map"][$key] : $default);
		}

		public function GetEditableFields()
		{
			return $this->user_info["writable"];
		}

		public function SetField($key, $value)
		{
			if (!isset($this->user_info["writable"][$key]))  return false;
			$this->user_info["field_map"][$key] = $value;

			return true;
		}

		public function GetData($key, $default = false)
		{
			if (isset($this->user_cache["data"][$key]))  return $this->user_cache["data"][$key];
			if (isset($this->user_cache["dbdata"][$key]))  return $this->user_cache["dbdata"][$key];

			return $default;
		}

		public function SetData($key, $value, $maxcookielen = 50)
		{
			if (isset($this->user_cache["data"][$key]) && $this->user_cache["data"][$key] === $value)  return false;
			if (isset($this->user_cache["dbdata"][$key]) && $this->user_cache["dbdata"][$key] === $value)  return false;

			if (strlen($key) + strlen($value) > $maxcookielen)
			{
				$this->user_cache["dbdata"][$key] = $value;
				$this->user_cache["dbchanged"] = true;
				$this->user_cache["hasdb"] = true;

				if (isset($this->user_cache["data"][$key]))
				{
					unset($this->user_cache["data"][$key]);
					$this->user_cache["changed"] = true;
				}
			}
			else
			{
				$this->user_cache["data"][$key] = $value;
				$this->user_cache["changed"] = true;

				if (isset($this->user_cache["dbdata"][$key]))
				{
					unset($this->user_cache["dbdata"][$key]);
					$this->user_cache["dbchanged"] = true;
					$this->user_cache["hasdb"] = count($this->user_cache["dbdata"]) > 0;
				}
			}

			return true;
		}

		public function GetMappedUserInfo($fieldmap, $object = true, $save = true)
		{
			$result = ($object ? new stdClass() : array());

			if (!$this->UserLoaded())
			{
				// Load local information from the encrypted cookie.
				foreach ($fieldmap as $fieldkey => $datakey)
				{
					if (is_int($fieldkey))  $fieldkey = $datakey;

					$val = $this->GetData($datakey);

					// If the cookie data is too long, false will be returned, so load the official data.
					if ($val === false)
					{
						if (!$this->LoadUserInfo())
						{
							echo htmlspecialchars($this->Translate("SSO client unable to load user information from the SSO server.  The server may be offline or overloaded."));
							exit();
						}

						break;
					}

					// Update the user object/array.
					if ($object)  $result->$fieldkey = $val;
					else  $result[$fieldkey] = $val;
				}
			}

			if ($this->UserLoaded())
			{
				// Refresh local information from the SSO server data.
				foreach ($fieldmap as $fieldkey => $datakey)
				{
					if (is_int($fieldkey))  $fieldkey = $datakey;

					$val = $this->GetField($fieldkey);

					// Save the data for later.
					$this->SetData($datakey, $val);

					// Update the user object/array.
					if ($object)  $result->$fieldkey = $val;
					else  $result[$fieldkey] = $val;
				}
			}

			// Load the user ID.
			if ($object)  $result->ID = $this->GetUserID();
			else  $result["ID"] = $this->GetUserID();

			// Send the browser cookies if the caller requested it.
			if ($save)  $this->SaveUserInfo();

			return $result;
		}

		public function SaveUserInfo($usedb = false)
		{
			if ($this->user_cache["changed"])
			{
				$cdata = array("c" => $this->user_cache["ts"], "s" => $this->user_info["sso_id"], "i" => $this->user_info["id"], "e" => $this->user_info["extra"]);
				if (count($this->user_info["tag_map"]))
				{
					$cdata["t"] = $this->user_info["tag_map"];
					foreach ($cdata["t"] as $key => $val)  $cdata["t"][$key] = 1;
				}
				if ($this->user_info["admin"])  $cdata["a"] = 1;
				if ($usedb && $this->user_cache["hasdb"])  $cdata["b"] = 1;
				if (count($this->user_cache["data"]))  $cdata["d"] = $this->user_cache["data"];
				$cdata["p"] = $this->user_cache["ipaddr"];
				$cdata = @json_encode($cdata);

				if (function_exists("gzcompress") && function_exists("gzuncompress"))  $cdata = "1:" . @gzcompress($cdata);
				else  $cdata = "0:" . $cdata;
				$vdata = hash_hmac("sha1", $cdata . ":" . SSO_SERVER_APIKEY, pack("H*", SSO_CLIENT_RAND_SEED6), true);
				$vdata = str_replace(array("+", "/", "="), array("-", "_", ""), base64_encode($vdata));

				$mode = (SSO_COOKIE_CIPHER == "aes256" ? "aes256" : "blowfish");
				$key = pack("H*", SSO_CLIENT_RAND_SEED);
				$options = array("prefix" => $this->rng->GenerateToken(), "mode" => "CBC", "iv" => pack("H*", SSO_CLIENT_RAND_SEED2), "lightweight" => true);
				if (SSO_COOKIE_DUAL_ENCRYPT)
				{
					$options["key2"] = pack("H*", SSO_CLIENT_RAND_SEED4);
					$options["iv2"] = pack("H*", SSO_CLIENT_RAND_SEED5);
				}

				if ($mode == "aes256")  $cdata = SSO_ExtendedAES::CreateDataPacket($cdata, $key, $options);
				else  $cdata = SSO_Blowfish::CreateDataPacket($cdata, $key, $options);

				$cdata = str_replace(array("+", "/", "="), array("-", "_", ""), base64_encode($cdata));

				if (!isset($this->request[SSO_COOKIE_NAME . "_c"]))  $this->SetCookieFixDomain(SSO_COOKIE_NAME . "_c", "1", 0, SSO_COOKIE_PATH, "", SSO_COOKIE_SSL_ONLY);
				if (!isset($this->request[SSO_COOKIE_NAME . "_s"]) || $this->request[SSO_COOKIE_NAME . "_s"] != $cdata)  $this->SetCookieFixDomain(SSO_COOKIE_NAME . "_s", $cdata, (SSO_COOKIE_TIMEOUT > 0 ? time() + SSO_COOKIE_TIMEOUT : 0), SSO_COOKIE_PATH, "", SSO_COOKIE_SSL_ONLY, true);
				if (!isset($this->request[SSO_COOKIE_NAME . "_v"]) || $this->request[SSO_COOKIE_NAME . "_v"] != $vdata)  $this->SetCookieFixDomain(SSO_COOKIE_NAME . "_v", $vdata, (SSO_COOKIE_TIMEOUT > 0 && !SSO_COOKIE_EXIT_TIMEOUT ? time() + SSO_COOKIE_TIMEOUT : 0), SSO_COOKIE_PATH, "", SSO_COOKIE_SSL_ONLY, true);

				$this->user_cache["changed"] = false;
			}
		}

		public function GetUserID()
		{
			return $this->user_info["id"];
		}

		public function GetSecretToken()
		{
			return hash_hmac("sha1", SSO_CLIENT_RAND_SEED16 . ":" . SSO_COOKIE_NAME . ":" . SSO_CLIENT_ROOT_PATH . ":" . $this->user_info["extra"], pack("H*", SSO_CLIENT_RAND_SEED15));
		}
	}

	// Adds a PHP session layer for additional server-side security and reduced cookie size.
	class SSO_Client extends SSO_Client_Base
	{
		private $sessionkey, $loggedinresult;

		public function SetCookieFixDomain($name, $value = "", $expires = 0, $path = "", $domain = "", $secure = false, $httponly = false)
		{
			if ($path === SSO_COOKIE_PATH && substr($name, 0, strlen(SSO_COOKIE_NAME)) === SSO_COOKIE_NAME)
			{
				// If cookies are written after SaveUserInfo() is called, the session will need to be reopened.
				$_SESSION[$this->sessionkey]["cookies"][substr($name, strlen(SSO_COOKIE_NAME))] = $value;
			}

			parent::SetCookieFixDomain($name, $value, $expires, $path, $domain, $secure, $httponly);
		}

		public function LoggedIn()
		{
			if (is_bool($this->loggedinresult))  return $this->loggedinresult;

			$this->loggedinresult = false;

			if (!parent::LoggedIn())  return false;

			// Validate the session cookie against the internal session data.
			if ($_SESSION[$this->sessionkey]["ipaddr"] !== $this->user_cache["ipaddr"] && $this->user_info["loaded"])
			{
				$_SESSION[$this->sessionkey]["ipaddr"] = $this->user_cache["ipaddr"];
			}

			if ($_SESSION[$this->sessionkey]["ipaddr"] !== $this->user_cache["ipaddr"] || (isset($_SESSION[$this->sessionkey]["cookies"]["_s"]) && isset($this->request[SSO_COOKIE_NAME . "_s"]) && $_SESSION[$this->sessionkey]["cookies"]["_s"] !== $this->request[SSO_COOKIE_NAME . "_s"]) || (isset($_SESSION[$this->sessionkey]["cookies"]["_v"]) && isset($this->request[SSO_COOKIE_NAME . "_v"]) && $_SESSION[$this->sessionkey]["cookies"]["_v"] !== $this->request[SSO_COOKIE_NAME . "_v"]))
			{
				// Assume the session was hijacked if the SSO server check has already happened.
				if ($this->user_info["loaded"])
				{
					// Avoid an infinite loop but force a logout.
					$_SESSION[$this->sessionkey]["cookies"] = array();

					return false;
				}

				// Validate the login.  Handle scenarios where the SSO Server is unavailable.
				$options = array(
					"sso_id" => $this->user_info["sso_id"],
					"expires" => (SSO_COOKIE_TIMEOUT > 0 && SSO_COOKIE_TIMEOUT < SSO_SERVER_SESSION_TIMEOUT ? SSO_COOKIE_TIMEOUT : SSO_SERVER_SESSION_TIMEOUT)
				);

				$result = $this->SendRequest("getlogin", $options);
				if (!$result["success"] && !isset($result["info"]))
				{
					$this->user_info["sso_id"] = "";

					return false;
				}
				if ($result["success"])
				{
					$this->ProcessLogin($result);

					$_SESSION[$this->sessionkey]["ipaddr"] = $this->user_cache["ipaddr"];
				}
				else if ($_SESSION[$this->sessionkey]["ipaddr"] !== $this->user_cache["ipaddr"])
				{
					$this->user_info["sso_id"] = "";

					return false;
				}
			}

			$this->loggedinresult = true;

			return true;
		}

		protected function ProcessLogin($info, $fromserver = false)
		{
			parent::ProcessLogin($info, $fromserver);

			// Reset local data set.  Otherwise clients might use stale content.
			$_SESSION[$this->sessionkey]["data"] = array();
		}

		public function Init($removekeys = array())
		{
			$this->sessionkey = "__sso_client_" . SSO_COOKIE_PATH . "_" . SSO_COOKIE_NAME;
			$this->loggedinresult = "invalid";

			@session_start();

			if (!isset($_SESSION[$this->sessionkey]))
			{
				$ipaddr = self::GetRemoteIP();

				$_SESSION[$this->sessionkey] = array(
					"cookies" => array(),
					"data" => array(),
					"ipaddr" => ($ipaddr["ipv4"] != "" && strlen($ipaddr["ipv4"]) < strlen($ipaddr["shortipv6"]) ? $ipaddr["ipv4"] : $ipaddr["shortipv6"]),
					"shortipv6" => $ipaddr["shortipv6"]
				);
			}

			parent::Init($removekeys);
		}

		public function CanRemoteLogin()
		{
			if (!parent::CanRemoteLogin())  return false;

			if ($_SESSION[$this->sessionkey]["shortipv6"] !== $this->ipaddr["shortipv6"] || (isset($_SESSION[$this->sessionkey]["cookies"]["_sr_id"]) && $_SESSION[$this->sessionkey]["cookies"]["_sr_id"] !== $this->request[SSO_COOKIE_NAME . "_sr_id"]) || (isset($_SESSION[$this->sessionkey]["cookies"]["_sr_t"]) && $_SESSION[$this->sessionkey]["cookies"]["_sr_t"] !== $this->request[SSO_COOKIE_NAME . "_sr_t"]))
			{
				// IP address changed or the cookies were hijacked.
				return false;
			}

			return true;
		}

		public function GetData($key, $default = false)
		{
			if (isset($_SESSION[$this->sessionkey]["data"][$key]))  return $_SESSION[$this->sessionkey]["data"][$key];

			return $default;
		}

		public function SetData($key, $value, $maxcookielen = 50)
		{
			if (isset($_SESSION[$this->sessionkey]["data"][$key]) && $_SESSION[$this->sessionkey]["data"][$key] === $value)  return false;

			$_SESSION[$this->sessionkey]["data"][$key] = $value;
			$this->user_cache["changed"] = true;

			if (isset($this->user_cache["dbdata"][$key]))
			{
				unset($this->user_cache["dbdata"][$key]);
				$this->user_cache["dbchanged"] = true;
				$this->user_cache["hasdb"] = count($this->user_cache["dbdata"]) > 0;
			}

			return true;
		}
	}
?>