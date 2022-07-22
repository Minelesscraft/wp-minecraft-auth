<?php

/**
 * Class for Auth functions
 *
 * @package     wp-minecraft-auth
 * @subpackage  Xbox Live OAuth
 * @copyright   Copyright (c) 2022, Visual Technology Solutions
 * @license     http://opensource.org/licenses/gpl-2.0.php GNU Public License
 * @since       1.0
 */

// Prevent loadinng outside of Wordpress
if ( ! defined( 'ABSPATH' ) ) exit;

class WPMAuth_XboxLive {
    private $plugin;

    private $_xbl_response;
    private $_xbl_array;

    private $_xsts_response;
    private $_xsts_array;

    public $xbl_issued;
    public $xbl_expires;
    public $xbl_token;
    public $xbl_userhash;

    public $xsts_issued;
    public $xsts_expires;
    public $xsts_token;
    public $xsts_userhash;

    public function __construct( $instance ) {
        $this->plugin = $instance;
        $this->_load_session_data();
    }

    public function authenticate_xbl( $token ) {
        $this->plugin->write_log( 'Authenticate XBL: ' . $token );

        $endpoint = $this->plugin->settings->endpoints->xbl;

        $body = array(
            'Properties' => array(
                'AuthMethod' => 'RPS',
                'SiteName' => 'user.auth.xboxlive.com',
                'RpsTicket' => 'd=' . $token,
            ),
            'RelyingParty' => 'http://auth.xboxlive.com',
            'TokenType' => 'JWT',
        );

        $this->_xbl_response = $this->_token_endpoint( $endpoint, $body );

        $this->_xbl_array = json_decode( $this->_xbl_response[ 'body' ], true );

        $this->plugin->write_log( 'XBL Token Array' );
        $this->plugin->write_log( $this->_xbl_array );

        if ( is_array( $this->_xbl_array ) && array_key_exists( 'xErr', $this->_xbl_array ) ) {
            $this->_parse_error( $this->_xbl_array );
            return false;
        }

        //$this->plugin->session->xboxlive_token_response = $this->_xbl_response;
        $this->plugin->session->xboxlive_token_array = $this->_xbl_array;

        return ( $this->_parse_response( $this->_xbl_array, 'xbl' ) ) ? $this->authenticate_xsts( $this->xbl_token ) : false;
    }

    public function authenticate_xsts( $token ) {
        $endpoint = $this->plugin->settings->endpoints->xsts;

        $body = array(
            'Properties' => array(
                'SandboxId' => 'RETAIL',
                'UserTokens' => array(
                    $token,
                ),
            ),
            'RelyingParty' => 'rp://api.minecraftservices.com',
            'TokenType' => 'JWT',
        );

        $this->_xsts_response = $this->_token_endpoint( $endpoint, $body );

        $this->plugin->write_log( 'XSTS Token Response' );
        $this->plugin->write_log( $this->_xsts_response );

        $this->_xsts_array = json_decode( $this->_xsts_response[ 'body' ], true );

        $this->plugin->write_log( 'XSTS Token Array' );
        $this->plugin->write_log( $this->_xsts_array );

        if ( is_array( $this->_xsts_array ) && array_key_exists( 'xErr', $this->_xsts_array ) ) {
            $this->_parse_error( $this->_xsts_array );
            return false;
        }

        //$this->plugin->session->xboxlive_xsts_response = $this->_xsts_response;
        $this->plugin->session->xboxlive_xsts_array = $this->_xsts_array;

        return $this->_parse_response( $this->_xsts_array, 'xsts' );
    }

    private function _token_endpoint( $endpoint, $body ) {
        $headers = array(
            'Accept'        => 'application/json',
            'charset'       => 'UTF - 8',
            'Content-Type'  => 'application/json',
        );

        $args = array(
            'method'        => 'post',
            'timeout'       => 45,
            'redirection'   => 5,
            'httpversion'   => '1.1',
            'blocking'      => true,
            'headers'       => $headers,
            'body'          => json_encode( $body ),
            'cookies'       => array(),
            'sslverify'     => true,
        );

        $response = wp_remote_post( $endpoint, $args );
        
        return $response;
    }

    private function _parse_response( $response, $type, $sub = false ) {
        $this->plugin->write_log( 'Xbox Live Parse Array: ' . $type );
        if ( ! is_array( $response ) ) {
            $this->plugin->add_error( 'Parse Response Array ' . $type, $type . ' response is not an array.' );
            exit();
        }

        if ( ! array_key_exists( 'Token', $response ) && $sub == false ) {
            $this->plugin->add_error( 'Parse Response Array ' . $type, 'No Token returned for ' . $type . '.' );
            return false;
        }

        foreach( $response as $key => $value ) {
            $this->plugin->write_log( 'Loop ' . $key . ' Value:' );
            $this->plugin->write_log( $value );

            if ( is_array( $value ) ) {
                $this->_parse_response( $value, $type, true );
                continue;
            }

            switch ( $key ) {
                case 'uhs':
                    if ( $type == 'xbl' ) {
                        $this->_xbl_userhash = $value;
                    } else {
                        $this->_xsts_userhash = $value;
                    }
                    break;
                
                case 'IssueInstant':
                    if ( $type == 'xbl' ) {
                        $this->_xbl_issued = $value;
                    } else {
                        $this->_xsts_issued = $value;
                    }
                    break;

                case 'NotAfter':
                    if ( $type == 'xbl' ) {
                        $this->_xbl_expires = $value;
                    } else {
                        $this->_xsts_expires = $value;
                    }
                    break;

                case 'Token':
                    if ( $type == 'xbl' ) {
                        $this->_xbl_token = $this->_decode_jwt( $value );
                    } else {
                        $this->_xsts_token = $this->_decode_jwt( $value );
                    }
                    break;
            }
        }

        $this->plugin->write_log( 'Xbox Live Parse Array Complete' );
        return true;
    }

    private function _load_session_data() {
        if ( ! $this->plugin->session->hasSession() ) {
            return false;
        }

        $xbl_result = false;
        $xsts_result = false;

        $xbl_response = $this->plugin->session->get( 'xboxlive_token_response', false );
        if ( $xbl_response !== false ) {
            $this->_xbl_response = $xbl_response;
        }

        $xbl_array = $this->plugin->session->get( 'xboxlive_token_array', false );
        if ( $xbl_array !== false ) {
            $this->_xbl_array = $xbl_array;
            $xbl_result = $this->_parse_response( $xbl_array, 'xbl' );
        }

        $xsts_response = $this->plugin->session->get( 'xboxlive_xsts_response', false );
        if ( $xsts_response !== false ) {
            $this->_xsts_response = $xsts_response;
        }

        $xsts_array = $this->plugin->session->get( 'xboxlive_xsts_array', false );
        if ( $xsts_array !== false ) {
            $this->_xsts_array = $xsts_array;
            $xsts_result = $this->_parse_response( $xsts_array, 'xsts' );
        }

        return $xbl_result && $xsts_result;
    }

    private function _parse_error( $error ) {
        $message = $error[ 'Message' ];

        if ( empty( $message ) ) {
            switch( (int)$error[ 'xErr' ] ) {
                case 2148916233:
                    $message = 'The account doesn\'t have an Xbox account. Once you sign up for one (or login through minecraft.net to create one) then you can proceed with the login.';
                    break;

                case 2148916235:
                    $message = 'This account is from a country where Xbox Live is not available or has been banned from Xbox Live.';
                    break;

                case 2148916236:
                case 2148916237:
                    $message = 'The account needs adult verification on Xbox page.';
                    break;

                case 2148916238:
                    $message = 'The account is a minor (under 18) and cannot proceed unless the account is added to a Microsoft Family by an adult.';
                    break;

            }
        }

        $this->plugin->add_error( $error[ 'xErr' ], $message );
        exit();
    }

    private function _decode_jwt( $token ) {
        return json_decode( base64_decode( str_replace( '_', '/', str_replace( '-', '+', explode( '.', $token )[ 1 ] ) ) ) );
    }
}