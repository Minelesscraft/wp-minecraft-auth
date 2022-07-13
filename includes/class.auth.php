<?php

/**
 * Class for Auth functions
 *
 * @package     wp-minecraft-auth
 * @subpackage  Wordpress Auth Api
 * @copyright   Copyright (c) 2022, Visual Technology Solutions
 * @license     http://opensource.org/licenses/gpl-2.0.php GNU Public License
 * @since       1.0
 */

// Prevent loadinng outside of Wordpress
if ( ! defined( 'ABSPATH' ) ) exit;

class wpmauth_auth {

    public static function ms_auth ($query) {
        global $wp;
        if ( $wp->request == 'ms-auth' ) {
            wp_die( 'Page hooked!', 'MS-Auth' );
        }
    }

}

add_action ( 'pre_get_posts', array ( 'wpmauth_auth', 'ms_auth' ) );