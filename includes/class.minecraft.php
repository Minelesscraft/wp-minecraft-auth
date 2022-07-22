<?php

/**
 * Class for Auth functions
 *
 * @package     wp-minecraft-auth
 * @subpackage  Minecraft OAuth
 * @copyright   Copyright (c) 2022, Visual Technology Solutions
 * @license     http://opensource.org/licenses/gpl-2.0.php GNU Public License
 * @since       1.0
 */

//namespace WPMinecraftAuth;

// Prevent loadinng outside of Wordpress
if ( ! defined( 'ABSPATH' ) ) exit;

class WPMAuth_Minecraft {
    private $plugin;

    private $_token_response;
    private $_token_array;

    public $access_token;
    public $expires;
    public $token_type;

    public function __construct( $instance ) {
        $this->plugin = $instance;
        $this->_load_session_data();
    }

    public function authenticate( $token, $hash ) {
        $this->_token_response = $this->_token_endpoint( $token, $hash );
        $this->_token_array = json_decode( $this->_token_response[ 'body' ], true );

        if ( ! array_key_exists( 'access_token', $this->_token_array ) ) {
            return false;
        }

        $this->plugin->session->minecraft_token_response = $this->_token_response;
        $this->plugin->session->minecraft_token_array = $this->_token_array;

        return $this->_parse_token();
    }

    public function get_entitlement() {
        $response = $this->_api_endpoint( '/entitlements/mcstore' );
        $res_arr = json_decode( $response[ 'body' ], true );

        return $res_arr;
    }

    public function get_profile() {
        $response = $this->_api_endpoint( '/minecraft/profile');
        $res_arr = json_decode( $response[ 'body' ], true );

        return $res_arr;
    }

    private function _api_endpoint( $endpoint, $method = 'get', $body = '' ) {
        if ( ! isset( $this->access_token ) ) {
            $this->plugin->add_error( 'Session', 'Failed to get sesssion. Token response.' );
        }

        $endpoint = 'https://api.minecraftservices.com' . $endpoint;

        $headers = array(
            'Accept'        => 'application/json',
            'charset'       => 'UTF - 8',
            'Content-Type'  => 'application/json',
            'Authorization' => $this->token_type . ' ' . $this->access_token,
        );

        $args = array(
            'method'        => $method,
            'timeout'       => 45,
            'redirection'   => 5,
            'httpversion'   => '1.1',
            'blocking'      => true,
            'headers'       => $headers,
            'body'          => $body,
            'cookies'       => array(),
            'sslverify'     => true,
        );

        $response = wp_remote_request( $endpoint, $args );
        
        return $response;
    }

    private function _parse_token() {
        if ( is_array( $this->_token_array ) ) {
            $this->plugin->add_error( 'Parse Response Arr ' . $type, 'Response is not an array.' );
            return false;
        }

        $access_token = false;
        $expires = false;
        $token_type = false;

        foreach( $this->_token_array as $key => $value ) {
            switch( $key ) {
                case 'access_token':
                    $this->access_token = $value;
                    $access_token = true;
                    break;

                case 'token_type':
                    $this->token_type = $value;
                    $token_type = true;
                    break;

                case 'expires_in':
                    $this->expires = time() + $value;
                    $expires = true;
                    break;
            }
        }

        return $access_token && $expires && $token_type;
    }

    private function _token_endpoint( $token, $hash ) {
        $endpoint = $this->plguin->settings->endpoints->mc;

        $headers = array(
            'Accept'        => 'application/json',
            'charset'       => 'UTF - 8',
            'Content-Type'  => 'application/json',
            'identityToken' => 'XBL3.0 x=' . $hash . ';' . $token,
        );

        $args = array(
            'method'        => 'post',
            'timeout'       => 45,
            'redirection'   => 5,
            'httpversion'   => '1.1',
            'blocking'      => true,
            'headers'       => $headers,
            'body'          => array(),
            'cookies'       => array(),
            'sslverify'     => true,
        );

        $response = wp_remote_post( $endpoint, $args );
        
        return $response;
    }
    
    private function _decode_jwt( $token ) {
        return json_decode( base64_decode( str_replace( '_', '/', str_replace( '-', '+', explode( '.', $token )[ 1 ] ) ) ) );
    }
}