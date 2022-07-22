<?php

/**
 * Class for Auth functions
 *
 * @package     wp-minecraft-auth
 * @subpackage  Wordpress User
 * @copyright   Copyright (c) 2022, Visual Technology Solutions
 * @license     http://opensource.org/licenses/gpl-2.0.php GNU Public License
 * @since       1.0
 */

// Prevent loadinng outside of Wordpress
if ( ! defined( 'ABSPATH' ) ) exit;

class WPMAuth_User {
    private $_plugin;
    private _id;

    public username;
    public email;
    public first_name;
    public last_name;
    public website;
    public password;

    function __construct() {
        $this->_plugin = wp_minecraft_auth();
    }
    
    private _wp_update_user() {
        
    }

    private _wp_login_user( $user ) {
        if ( is_numeric( $user ) ) {
            $user = get_user_by( 'id', $user );
        } elseif ( is_string( $user ) ) {
            $user = get_user_by( 'login', $user );
        }

        if ( is_object( $user) && $user instanceof WP_User ) {
            wp_set_current_user( $user->ID );
            wp_set_auth_cookie( $user->ID );

            do_action( 'wp_login', $user->user_login, $user );
        }
    }
}