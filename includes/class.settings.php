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

class WPMAuth_Settings {
    private $_plugin;
    private $_data = array();
    private $_dirty = false;

    function __construct( $instance ) {
        $this->_plugin = $instance;
        $this->_data = get_option( 'wp_minecraft_auth', false );

        if ( $this->_data === false ) {
            $this->_defaults();
            $this->save();
        }

        require_once WPMAUTH_PATH . 'includes/class.sub_array.php';

        add_action( 'shutdown', array( $this, 'save') );
        $this->_plugin->write_log( $this->_data );
    }

    function __isset( $key ) {
        return isset( $this->_data[ sanitize_title( $key ) ] );
    }

    function __get( $key ) {
        if ( ! array_key_exists( $key, $this->_data ) ) {
            return null;
        }

        if ( is_array( $this->_data[ $key ] ) ) {
            return new WPMAuth_SubArray( $this->_data[ $key ], $this->_dirty );
        } else {
            return $this->_data[ $key ];
        }
    }

    function __set( $key, $value ) {
        if ( $value !== $this->_data[ $key ] ) {
            $this->_data[ sanitize_key( $key ) ] = $value;
            $this->_dirty = true;
        }
    }

    function __unset( $key ) {
        if ( isset( $this->_daya[ $key ] ) ) {
            unset( $this->_data[$key] );
            $this->_dirty = true;
        }
    }

    function refresh() {
        $this->_data = get_option( 'wp_minecraft_auth' );
    }

    function save() {
        if ( $this->_dirty ) {
            update_option( 'wp_minecraft_auth', $this->_data, false );
            $this->_dirty = false;
        }
    }

    private function _defaults() {
        $defaults = array(
            'first_run' => 1,
            'debug' => 0,
            'oauth' => array(
                'client_id' => '',
                'client_secret' => '',
                'client_scope' => 'XboxLive.signin offline_access email profile openid',
            ),
            'endpoints' => array(
                'authorization' => 'https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize',
                'token' => 'https://login.microsoftonline.com/consumers/oauth2/v2.0/token',
                'xbl' => 'https://user.auth.xboxlive.com/user/authenticate',
                'xsts' => 'https://xsts.auth.xboxlive.com/xsts/authorize',
                'mc' => 'https://api.minecraftservices.com/authentication/login_with_xbox',
            ),
        );

        $this->_data = $defaults;
        $this->_dirty = true;
    }
}