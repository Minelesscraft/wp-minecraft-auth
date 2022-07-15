<?php

/**
 * Class for Auth functions
 *
 * @package     wp-minecraft-auth
 * @subpackage  WP-Minecraft-Auth Settings
 * @copyright   Copyright (c) 2022, Visual Technology Solutions
 * @license     http://opensource.org/licenses/gpl-2.0.php GNU Public License
 * @since       1.0
 */

// Prevent loadinng outside of Wordpress
if ( ! defined( 'ABSPATH' ) ) exit;

// wpmauth_first_run
// wpmauth_appname
// wpmauth_client_id
// wpmauth_client_secret
// wpmauth_client_scope
// wpmauth_authorization_url
// wpmauth_token_endpoint_url

class wpmauth_settings {
    function __construct() {
        if ( get_option( 'wpmauth_first_run' ) === false ) {
            add_action( 'init', array( $this, 'defaults' ), 10 );
        }
    }

    function defaults() {
        update_option( 'wpmauth_first_run', 1, false);
        update_option( 'wpmauth_app_name', '', false);
        update_option( 'wpmauth_client_id', '', false);
        update_option( 'wpmauth_client_secret', '', false);
        update_option( 'wpmauth_client_scope', 'XboxLive.signin offline_access', false);
        update_option( 'wpmauth_authorization_url', 'https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize', false);
        update_option( 'wpmauth_token_endpoint_url', 'https://login.microsoftonline.com/consumers/oauth2/v2.0/token', false);
    }
}