<?php
require_once dirname(__FILE__) . '/vendor/autoload.php';
// require_once dirname(__FILE__) . '/restricted_site_access.php';

class WSCUserCheck {
	/**
	 * Plugin options.
	 *
	 * @var array $rsa_options The plugin options.
	 */
	private static $rsa_options;

	/**
	 * Settings fields.
	 *
	 * @var array $fields The plugin settings fields.
	 */
	private static $fields;

	/**
	 * Handles initializing this class and returning the singleton instance after it's been cached.
	 *
	 * @return null|Restricted_Site_Access
	 * @codeCoverageIgnore
	 */
	public static function get_instance() {
		// Store the instance locally to avoid private static replication.
		static $instance = null;

		if ( null === $instance ) {
			$instance = new self();
			self::populate_fields_array();
			self::restrict_access();
		}

		return $instance;
	}
	/**
	 * An empty constructor
	 *
	 * @codeCoverageIgnore
	 */
	public function __construct() {
		/* Purposely do nothing here */ }


	/**
	 * Populate Restricted_Site_Access::$fields with internationalization-ready field information.
	 *
	 * @codeCoverageIgnore
	 */
	protected static function populate_fields_array() {
		self::$fields = array(
			'approach'      => array(
				'default' => 1,
				'field'   => 'settings_field_handling',
			),
			'message'       => array(
				'default' => 'Access to this site is restricted.',
				'field'   => 'settings_field_message',
			),
			'redirect_url'  => array(
				'default' => '',
				'field'   => 'settings_field_redirect',
			),
			'redirect_path' => array(
				'default' => 0,
				'field'   => 'settings_field_redirect_path',
			),
			'head_code'     => array(
				'default' => 302,
				'field'   => 'settings_field_redirect_code',
			),
			'page'          => array(
				'default' => 0,
				'field'   => 'settings_field_rsa_page',
			),
			'allowed'       => array(
				'default' => array(),
				'field'   => 'settings_field_allowed',
			),
		);
	}

	/**
	 * Populate the option with defaults.
	 *
	 * @param boolean $network Whether this is a network install. Default false.
	 */
	public static function get_options( $network = false ) {
		$options = array();

		$options = [
			'redirect_url' => RSA_REDIRECT ?? '',
			'approach' => RSA_REDIRECT !== null ? 2 : 1,
			'allowed' => RSA_IP_WHITELIST !== null ? explode('|', RSA_IP_WHITELIST) : ''
		];

		// Fill in defaults where values aren't set.
		foreach ( self::$fields as $field_name => $field_details ) {
			if ( ! isset( $options[ $field_name ] ) ) {
				$options[ $field_name ] = $field_details['default'];
			}
		}

		return $options;
	}

	public static function restrict_access(){
	    global $wp;
	    $results = self::restrict_access_check( $wp );

	    if ( is_array( $results ) && ! empty( $results ) ) {

	        /**
	         * This conditional prevents a redirect loop if the redirect URL
	         * belongs to the same domain.
	         */
	        if ( 2 === self::$rsa_options['approach'] ) {
	        	$url = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . "://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";
	            $redirect_url_without_scheme = rtrim( preg_replace( '(^https?://)', '', $results['url'] ), '/\\' ) . '/';
	            $current_url_without_scheme  = rtrim(preg_replace( '(^https?://)', '', parse_url( $url, PHP_URL_HOST ) ), '/\\' ) . '/';
	            $current_url_path            = rtrim(parse_url( $url, PHP_URL_PATH ), '/\\' ) . '/';

	            if ( ( $current_url_path === $redirect_url_without_scheme ) || ( $redirect_url_without_scheme === $current_url_without_scheme ) ) {
	                return;
	            }
	        }

			// Don't redirect during unit tests.
			if ( ! empty( $results['url'] ) && ! defined( 'PHP_UNIT_TESTS_ENV' ) ) {
				header( 'Location: ' . $results['url'], true, $results['code'] ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect
				die();
			}

			// Don't die during unit tests.
			if ( ! empty( $results['die_message'] ) && ! defined( 'PHP_UNIT_TESTS_ENV' ) ) {
				die($results['die_title'] . '<br>' .$results['die_code'] . '<br>' . $results['die_message']);
			}
	    }
	}

	public static function restrict_access_check($wp) {
	    self::$rsa_options = self::get_options();
	    $is_restricted     = self::is_restricted();

	    if($is_restricted === false) {
	    	return;
	    }
	    // Check to see if we're activating new user.
	    if ( preg_match ('#^/wp-activate.php/#', $_SERVER['REQUEST_URI']) ) {
	        return;	
	    }

	    $allowed_ips = self::get_config_ips();
	    if (
	        ! empty( self::$rsa_options['allowed'] ) &&
	        is_array( self::$rsa_options['allowed'] )
	    ) {
	        $allowed_ips = array_merge( $allowed_ips, self::$rsa_options['allowed'] );
	    }

	    // check for the allow list, if its empty block everything.
	    if ( count( $allowed_ips ) > 0 ) {
	        $remote_ip = self::get_client_ip_address();

	        // iterate through the allow list.
	        foreach ( $allowed_ips as $line ) {
	            if ( self::ip_in_range( $remote_ip, $line ) ) {

	                /**
	                 * Fires when an ip address match occurs.
	                 *
	                 * Enables adding session_start() to the IP check, ensuring Varnish type cache will
	                 * not cache the request. Passes the matched line; previous to 6.1.0 this action passed
	                 * the matched ip and mask.
	                 *
	                 * @since 6.0.2
	                 *
	                 * @param string $remote_ip The remote IP address being checked.
	                 * @param string $line      The matched masked IP address.
	                 */
    				define('RSA_IP_AUTHORIZED', true);
	                return;
	            }
	        }
	    }

	    $rsa_restrict_approach = self::$rsa_options['approach'];

	    if($rsa_restrict_approach == 2){
            if ( ! empty( self::$rsa_options['redirect_url'] ) ) {
        		$url = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . "://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";
                $redirect_url_domain = self::$rsa_options['redirect_url'];
                if($url == $redirect_url) {
                	print_r('hellooo');
                	return;
                }
            }
        }

	    $redirect_url  = self::$rsa_options['redirect_url'];
	    $redirect_code = self::$rsa_options['head_code'];
	    
	    return array(
	        'url'  => $redirect_url,
	        'code' => $redirect_code,
	    );
	}

	/**
	 * Determine if site should be restricted
	 */
	protected static function is_restricted() {
		$blog_public = RSA_FORCE_RESTRICTION ? 2 : 1;

		$user_check = count(wpsc_get_auth_cookies());
		
    	$url = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . "://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";
		$is_login = preg_match ('#^/'. RSA_LOGIN_URL . '/#', $_SERVER['REQUEST_URI']);

		$checks = is_admin() || $is_login || $user_check || 2 !== (int) $blog_public || ( defined( 'WP_INSTALLING' ) && isset( $_GET['key'] ) ); // phpcs:ignore WordPress.Security.NonceVerification

		return ! $checks;
	}

	/**
	 * Retrieve the visitor ip address, even it is behind a proxy.
	 *
	 * @return string
	 */
	public static function get_client_ip_address() {
		$ip      = '';
		$headers = array(
			'HTTP_CF_CONNECTING_IP',
			'HTTP_CLIENT_IP',
			'HTTP_X_FORWARDED_FOR',
			'HTTP_X_FORWARDED',
			'HTTP_X_CLUSTER_CLIENT_IP',
			'HTTP_FORWARDED_FOR',
			'HTTP_FORWARDED',
			'REMOTE_ADDR',
		);
		foreach ( $headers as $key ) {

			if ( ! isset( $_SERVER[ $key ] ) ) {
				continue;
			}

			foreach ( explode(
				',',
				htmlspecialchars( stripslashes( $_SERVER[ $key ] ) )
			) as $ip ) {
				$ip = trim( $ip ); // just to be safe.

				if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) !== false ) {
					return $ip;
				}
			}
		}

		return $ip;
	}

	/**
	 * Is it a valid IP address? v4/v6 with subnet range.
	 *
	 * @param string $ip_address IP Address to check.
	 *
	 * @return bool True if its a valid IP address.
	 */
	public static function is_ip( $ip_address ) {
		// very basic validation of ranges.
		if ( strpos( $ip_address, '/' ) ) {
			$ip_parts = explode( '/', $ip_address );
			if ( empty( $ip_parts[1] ) || ! is_numeric( $ip_parts[1] ) || strlen( $ip_parts[1] ) > 3 ) {
				return false;
			}
			$ip_address = $ip_parts[0];
		}

		// confirm IP part is a valid IPv6 or IPv4 IP.
		if ( empty( $ip_address ) || ! inet_pton( stripslashes( $ip_address ) ) ) {
			return false;
		}

		return true;
	}

	/**
	 * Check if a given ip is in a network.
	 * Source: https://gist.github.com/tott/7684443
	 *
	 * @param  string $ip    IP to check in IPV4 format eg. 127.0.0.1.
	 * @param  string $range IP/CIDR netmask eg. 127.0.0.0/24, also 127.0.0.1 is accepted and /32 assumed.
	 * @return boolean true if the ip is in this range / false if not.
	 */
	public static function ip_in_range( $ip, $range ) {
	    $address = \IPLib\Factory::parseAddressString($ip);
	    $range = \IPLib\Factory::parseRangeString($range);

	    if($ip !== null && $range !== null) {
	        return($address->matches($range));
	    }
	}

	/**
	 * Gets an array of valid IP addresses from constant.
	 *
	 * @return array
	 */
	public static function get_config_ips() {
		if ( ! defined( 'RSA_IP_WHITELIST' ) || ! RSA_IP_WHITELIST ) {
			return array();
		}

		if ( ! is_string( RSA_IP_WHITELIST ) ) {
			return array();
		}

		// Filter out valid IPs from configured ones.
		$raw_ips   = explode( '|', RSA_IP_WHITELIST );
		$valid_ips = array();
		foreach ( $raw_ips as $ip ) {
			$trimmed = trim( $ip );
			if ( self::is_ip( $trimmed ) ) {
				$valid_ips[] = $trimmed;
			}
		}
		return $valid_ips;
	}
}

if(RSA_FORCE_RESTRICTION && WP_CACHE === true && function_exists('wpsc_get_auth_cookies')) {
	WSCUserCheck::get_instance();
}