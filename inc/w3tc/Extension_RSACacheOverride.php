<?php
namespace RSA\W3TC;

class Extension_RSACacheOverride {
	/**
	 * W3 Total cache config
	 */
	private $config;



	/**
	 * Runs extension
	 */
	function run() {
		// // obtain w3tc config
		require_once (__DIR__ . '/../../cache_override.php');
	}
}



/*
This file is simply loaded by W3 Total Cache in a case if extension is active.
Its up to extension what will it do or which way will it do.
*/
$p = new Extension_RSACacheOverride();
$p->run();

if ( is_admin() ) {
	require_once(__DIR__) . '/Extension_RSACacheOverride_Admin.php';
	$p = new Extension_RSACacheOverride_Admin();
	$p->run();
}
