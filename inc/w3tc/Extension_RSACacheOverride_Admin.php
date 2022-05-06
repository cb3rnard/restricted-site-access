<?php
namespace RSA\W3TC;

/**
 * Backend functionality of an extension.
 * This class is loaded only for wp-admin/ requests
 */
class Extension_RSACacheOverride_Admin {
	/**
	 * w3tc_extensions filter handler
	 *
	 * @param array   $extensions array of extension descriptors to fill
	 * @param Config  $config     w3-total-cache configuration
	 * @return array
	 */
	static public function w3tc_extensions( $extensions, $config ) {
		$extensions['rsa_cache_override'] = array (
			'name' => 'RSA Cache Override',
			'author' => 'Cbernard',
			'description' => __( 'Autoriser le check par IP ou utilisateur enregistré avant d\'activer le cache pour autoriser la redirection des visiteurs non autorisés.' ),
			'author_uri' => 'https://www.cbernard.fr/',
			// 'extension_uri' => 'https://www.w3-edge.com/',
			'extension_id' => 'rsa_cache_override',
			'settings_exists' => true,
			'version' => '1.0',
			'enabled' => true,
			'requirements' => '',
			'path' => 'restricted-site-access/inc/w3tc/Extension_RSACacheOverride.php'
		);

		return $extensions;
	}



	/**
	 * Entry point of extension for wp-admin/ requests
	 * Called from Extension_Example.php
	 */
	public function run() {
	// 	// handle settings page of this extension
	}
}