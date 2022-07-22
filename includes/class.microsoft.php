<?php

/**
 * Class for Auth functions
 *
 * @package     wp-minecraft-auth
 * @subpackage  Microsoft OAuth
 * @copyright   Copyright (c) 2022, Visual Technology Solutions
 * @license     http://opensource.org/licenses/gpl-2.0.php GNU Public License
 * @since       1.0
 */

//namespace WPMinecraftAuth;

// Prevent loadinng outside of Wordpress
if ( ! defined( 'ABSPATH' ) ) exit;

class WPMAuth_Microsoft {
    private $plugin;

    private $_verifier;
    private $_verifier_challenge;
    private $_verifier_challenge_method = 'S256';

    private $_token_response;
    private $_token_array;

    public $token_type;
    public $token_expires;
    public $token_scope;
    public $access_token;
    public $refresh_token;

    public function __construct( $instance ) {
        $this->plugin = $instance;
        $this->_load_session_data();
    }

    public function start_authentication( $force = false ) {
        $this->plugin->write_log( 'Microsoft: Start Authentication' );

        if ( $force ) {
            $this->_clear_session_data();
            $this->plugin->session->setUserSessionCookie( true );
        }

        if ( ! $this->plugin->session->hasSession() ) {
            $this->plugin->add_error( 'session', 'Failed to get session when attempting to setup authentication url.' );
        }

        $auth_url = $this->_generate_authorization_url();

        $this->plugin->write_log( 'Microsoft: Start Authentication Complete' );

        wp_redirect( $auth_url );
        exit();
    }

    public function authenticate_code( $code, $state ) {
        $this->plugin->write_log( 'Microsoft: Authentication Code' );

        if ( ! $this->_validate_state( $state ) ) {
            wp_nonce_ays( 'login-minecraft' );
        }

        $response = $this->_token_endpoint( $code, 'authorization_code' );
        $this->_token_array = json_decode( $response[ 'body' ], true );

        $this->plugin->write_log( 'Authenticate Code Token Array' );
        $this->plugin->write_log( $this->_token_array );

        if ( is_array( $this->_token_array ) && array_key_exists( 'error', $this->_token_array ) ) {
            $this->plugin->write_log( 'Microsoft: Token Error Occured' );
            $this->plugin->add_error( substr( $this->_token_array[ 'error_description' ], 0, 11 ), $this->_token_array[ 'error_description' ] );
            return false;
        }

        if ( is_array( $this->_token_array ) && array_key_exists( 'expires_in', $this->_token_array ) ) {
            $this->_token_array[ 'expires' ] = time() + $this->_token_array[ 'expires_in' ]; 
        }

        //$this->plugin->session->microsoft_token_response = $this->_token_response;
        $this->plugin->session->microsoft_token_array = $this->_token_array;

        $this->_parse_token_response();

        $this->plugin->write_log( 'Microsoft: Authentication Complete ' );
        return ( $response ) ? true : false;
    }

    public function get_token() {
        $this->plugin->write_log( 'Microsoft: Get Token' );
        if ( ! isset( $this->_token_array ) || ! is_array( $this->_token_array ) ) {
            $this->plugin->write_log( 'Microsoft: Get Token Array not Set' );
            $this->start_authentication();
            return false;
        }

        if ( $this->token_expires < strtotime( '+10 minutes' ) ) {
            if ( isset( $this->refresh_token ) && ! empty( $this->refresh_token ) ) {
                $this->plugin->write_log( 'Microsoft: Get Token Refreshing Via Token' );
                $response = $this->_token_endpoint( $this->refresh_token, 'refresh_token' );
                $this->_token_array = json_decode( $response[ 'body' ], true );

                $this->plugin->write_log( 'Refresh Token Array' );
                $this->plugin->write_log( $this->_token_array );

                if ( is_array( $this->_token_array ) && array_key_exists( 'error', $this-_token_array ) ) {
                    if ( substr( $_token_Array[ 'error_description' ], 0, 12 ) == 'AADSTS70008:' ) {
                        $this->plugin->write_log( 'Microsoft: Get Token Refresh Token Expired.' );
                        // Refresh Token expired
                        $this->start_authentication( true );
                        return false;
                    }
                    $this->plugin->write_log( 'Microsoft: Get Token Error Occured' );
                    $this->plugin->add_error( substr( $response[ 'error_description' ], 0, 11 ), $response[ 'error_description' ] );
                }

                if ( is_array( $this->_token_array ) && array_key_exists( 'expires_in', $this->_token_array ) ) {
                    $this->_token_array[ 'expires' ] = time() + $this->_token_array[ 'expires_in' ]; 
                }

                //$this->plugin->session->microsoft_token_response = $this->_token_response;
                $this->plugin->session->microsoft_token_array = $this->_token_array;

                $this->_parse_token_response();
            }
        }

        $this->plugin->write_log( 'Microsoft: Get Token Complete' );
        return ( is_array( $this->_token_array ) && array_key_exists( 'access_token', $this->_token_array ) ) ? $this->access_token : false;
    }

    public function get_profile() {
        $profile = $this->_api_endpoint( '/me' );

        return json_decode( $profile, true );
    }

    private function _clear_session_data() {
        $this->plugin->session->destroySession();

        unset( $this->_verifier );
        unset( $this->_verifier_challenge );
        unset( $this->_verifier_challenge_method );
        unset( $this->_token_response );
        unset( $this->_token_array );
        unset( $this->authentication_code );
        unset( $this->token_type );
        unset( $this->token_expires );
        unset( $this->token_scope );
        unset( $this->access_token );
        unset( $this->refresh_token );
    }

    private function _load_session_data() {
        if ( ! $this->plugin->session->hasSession() ) {
            return false;
        }

        $result = false;

        $verifier = $this->plugin->session->get( 'verifier', false );
        if ( $verifier ) {
            $this->_verifier = $verifier;
            $this->_generate_challenge();
        }

        $token_response = $this->plugin->session->get( 'microsoft_token_response', false );
        if ( $token_response !== false ) {
            $this->_token_response = $token_response;
        }

        $token_array = $this->plugin->session->get( 'microsoft_token_array', false );
        if ( $token_array !== false ) {
            $this->_token_array = $token_array;
            $result = $this->_parse_token_response();
        }

        return $result;
    }

    private function _authorization_endpoint() {
        if ( ! $this->plugin->session->hasSession() ) {
            $this->plugin->add_error( 'session', 'Failed to get sesssion. Authorization Endpoint.' );
            exit();
        }

        $auth_url = $this->_generate_authorization_url();

        $this->plugin->session->verifier = $this->_verifier;
        
        if ( isset( $_GET[ 'return_to' ] ) ) {
            $this->plugin->session->return_to = $_GET[ 'return_to' ];
        }
        
        $this->plugin->write_log( $auth_url );

        wp_redirect( $auth_url );
        exit();
    }

    private function _token_endpoint( $code, $grant_type ) {
        if ( ! $this->plugin->session->hasSession() ) {
            $this->plugin->add_error( 'Session', 'Failed to get sesssion. Token response.' );
            exit();
        }

        $token_url = $this->plugin->settings->endpoints->token;
        $client_id = $this->plugin->settings->oauth->client_id;
        $client_secret = $this->plugin->settings->oauth->client_secret;
        $client_scope = $this->plugin->settings->oauth->client_scope;

        $redirect_url = $this->plugin->get_return_url();

        $this->_verifier = $this->plugin->session->verifier;
        $this->_generate_challenge();

        $body = array(
            'grant_type'    => $grant_type,
            'redirect_uri'  => $redirect_url,
            'scope'         => $client_scope,
            'code_verifier' => $this->_verifier,
        );

        if ( $grant_type == 'refresh_token' ) {
            $body[ 'refresh_token' ] = $code;
        } else {
            $body[ 'code' ] = $code;
        }

        $headers = array(
            'Accept'        => 'application/json',
            'charset'       => 'UTF - 8',
            'Authorization' => 'Basic ' . base64_encode( $client_id . ':' .$client_secret ),
            'Content-Type'  => 'application/x-www-form-urlencoded',
        );

        $args = array(
            'method'        => 'post',
            'timeout'       => 45,
            'redirection'   => 5,
            'httpversion'   => '1.1',
            'blocking'      => true,
            'headers'       => $headers,
            'body'          => $body,
            'cookies'       => array(),
            'sslverify'     => true,
        );

        $this->_token_response = wp_remote_post( $token_url, $args );
        
        return $this->_token_response;
    }

    private function _api_endpoint( $endpoint, $method = 'get', $body = '' ) {
        if ( ! isset( $this->access_token ) ) {
            $this->plugin->add_error( 'Session', 'Failed to get sesssion. Token response.' );
        }

        $endpoint = 'https://graph.microsoft.com/v1.0' . $endpoint;

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

    private function _parse_token_response() {
        if ( ! is_array( $this->_token_array ) ) {
            $this->plugin->add_error( 'Microsoft Token Response', 'Failed to decode token array.' );
            exit();
        }

        if ( ! array_key_exists( 'access_token', $this->_token_array ) ) {
            // $this->plugin->add_error( 'Microsoft Token Response', 'Invalid response received. No access token included.' );
            return false;
        }

        foreach( $this->_token_array as $key => $value ) {
            switch( $key ) {
                case 'token_array':
                    $this->token_type = $value;
                    break;

                case 'expires':
                    $this->token_expires = $value;
                    break;

                case 'scope':
                    $this->token_scope = $value;
                    break;

                case 'access_token':
                    $this->access_token = $value;
                    break;
                
                case 'refresh_token':
                    $this->refresh_token = $value;
                    break;
            }
        }

        return true;
    }

    private function _generate_authorization_url() {
        $auth_url = $this->plugin->settings->endpoints->authorization;
        $client_id = $this->plugin->settings->oauth->client_id;
        $scope = $this->plugin->settings->oauth->client_scope;

        $this->_generate_challenge();
        
        $state = $this->_generate_state();
        $redirect_url = $this->plugin->get_return_url();
        
        if ( $auth_url === false || strlen( $auth_url ) == 0 || $client_id === false || strlen( $client_id ) == 0 ) {
            wp_die( 'Please configure WP Minecraft Auth', 'Minecraft OAuth Misconfigured' );
        }

        return $auth_url . '?client_id=' . $client_id . '&scope=' . urlencode( $scope ) . '&redirect_uri=' . $redirect_url . '&response_type=code&state=' . $state . '&code_challenge=' . $this->_challenge . '&code_challenge_method=' . $this->_challengeMethod;
    }

    private function _generate_challenge() {
        // Function to generate code verifier and code challenge for oAuth login. See RFC7636 for details. 
        $verifier = $this->_verifier;
        if ( ! $this->_verifier ) {
            $chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-._~';
            $charLen = strlen( $chars ) - 1;
            $verifier = '';
            for ( $i = 0; $i < 128; $i++ ) {
                $verifier .= $chars[ mt_rand( 0, $charLen ) ];
            }
            $this->_verifier = $verifier;
            if ( $this->plugin->session->hasSession() ) {
                $this->plugin->session->verifier = $verifier;
            }
        }

        // Challenge = Base64 Url Encode ( SHA256 ( Verifier ) )
        // Pack (H) to convert 64 char hash into 32 byte hex
        // As there is no B64UrlEncode we use strtr to swap +/ for -_ and then strip off the =
        $this->_challenge = str_replace( '=', '', strtr( base64_encode( pack( 'H*', hash( 'sha256', $verifier ) ) ), '+/', '-_' ) );
        $this->_challengeMethod = 'S256';
    }

    private function _generate_state() {
        $salt = 'minecraft-auth-' . COOKIEHASH;
        return wp_create_nonce( $salt );
    }

    private function _validate_state( $state ) {
        $salt = 'minecraft-auth-' . COOKIEHASH;
        return wp_verify_nonce( $state, $salt );
    }
}