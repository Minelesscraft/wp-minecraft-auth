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

class WPMAuth_OAuth {

    private $_plugin;

    private $_verifier;
    private $_challenge;
    private $_challengeMethod;

    function __construct( $instance ) {
        $this->_plugin = $instance;
    }

    function error( $code, $message, $extra = '' ) {
        if ( $this->_plugin->session->hasSession() ) {
            $this->_plugin->session->error = array( 'code' => $code, '$message' => $message );
            header('Location: ' . wp_login_url() );
        } else {
            $err = new WP_Error( $code, $message );
            wp_die( $err );
        }
        exit();
    }
    
    function authorizationEndpoint() {
        $authorizationUrl = $this->_generateAuthorizationUrl();

        print_r($authorizationUrl);

        if ( $this->_plugin->session->hasSession() ) {
            $this->_plugin->session->verifier = $this->_verifier;
            if ( isset( $_GET['return_to'] ) ) {
                $this->_plugin->session->return_to = $_GET['return_to'];
            }
        } else {
            $this->error( 'session', 'Failed to get sesssion. Authorization Endpoint.' );
        }

        $this->_plugin->write_log( $authorizationUrl );

        header('Location: ' . $authorizationUrl );
        exit;
    }

    function tokenEndpoint( $code, $grant_type ) {
        $token_url = $this->_plugin->settings->endpoints->token;
        $client_id = $this->_plugin->settings->oauth->client_id;
        $client_secret = $this->_plugin->settings->oauth->client_secret;
        $scope = $this->_plugin->settings->oauth->client_scope;

        $redirect_url = $this->getReturnUrl();

        if ( $this->_plugin->session->hasSession() ) {
            $this->_verifier = $this->_plugin->session->verifier;
            $this->_generateOAuthChallenge();
        } else {
            $this->error( 'session', 'Failed to get sesssion. Token Endpoint.' );
        }

        $body = array (
            'grant_type'    => $grant_type,
            'code'          => $code,
            // 'client_id'     => $client_id,
            //'client_secret' => $client_secret,
            'redirect_uri'  => $redirect_url,
            'scope'         => $scope,
            'code_verifier' => $this->_verifier,
        );

        $headers = array(
            'Accept'        => 'application/json',
            'charset'       => 'UTF - 8',
            'Authorization' => 'Basic ' . base64_encode( $client_id . ':' . $client_secret ),
            'Content-Type'  => 'application/x-www-form-urlencoded'
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
            'sslverify'     => true
        );

        $response = wp_remote_post( $token_url, $args );
        $response = $response['body'];
        $response = json_decode($response, true);

        $this->_plugin->write_log( $response );

        return $response;
    }

    function xblEndpoint( $token ) {
        $token_url = $this->_plugin->settings->endpoints->xbl;
        
        $redirect_url = $this->getReturnUrl();

        if ( $this->_plugin->session->hasSession() ) {
            $this->_verifier = $this->_plugin->session->verifier;
            $this->_generateOAuthChallenge();
        } else {
            $this->error( 'session', 'Failed to get sesssion. XBL Endpoint.' );
        }

        $body = array (
            'Properties' => array(
                'AuthMethod' => 'RPS',
                'SiteName' => 'user.auth.xboxlive.com',
                'RpsTicket' => 'd=' . $token,
            ),
            'RelyingParty' => 'http://auth.xboxlive.com',
            'TokenType' => 'JWT'
        );

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

        $response = wp_remote_post( $token_url, $args );
        $response = $response['body'];
        $response = json_decode($response, true);

        $this->_plugin->write_log( $response );

        return $response;
    }

    private function _generateAuthorizationUrl() {
        $auth_url = $this->_plugin->settings->endpoints->authorization;
        $client_id = $this->_plugin->settings->oauth->client_id;
        $scope = $this->_plugin->settings->oauth->client_scope;

        $this->_generateOAuthChallenge();
        
        $state = wp_create_nonce( 'mc-auth-login' );
        $redirect_url = $this->getReturnUrl();
        
        if ( $auth_url === false || strlen( $auth_url ) == 0 || $client_id === false || strlen( $client_id ) == 0 ) {
            wp_die( 'Please configure WP Minecraft Auth', 'Minecraft OAuth Misconfigured' );
        }

        return $auth_url . '?client_id=' . $client_id . '&scope=' . urlencode( $scope ) . '&redirect_uri=' . $redirect_url . '&response_type=code&state=' . $state . '&code_challenge=' . $this->_challenge . '&code_challenge_method=' . $this->_challengeMethod;
    }

    private function _generateOAuthChallenge() {
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
        }

        // Challenge = Base64 Url Encode ( SHA256 ( Verifier ) )
        // Pack (H) to convert 64 char hash into 32 byte hex
        // As there is no B64UrlEncode we use strtr to swap +/ for -_ and then strip off the =
        $this->_challenge = str_replace( '=', '', strtr( base64_encode( pack( 'H*', hash( 'sha256', $verifier ) ) ), '+/', '-_' ) );
        $this->_challengeMethod = 'S256';
    }

    function getReturnUrl() {
        return site_url( '/mc-auth' );
    }

    function base64UrlEncode ( $data ) {
        return str_replace( '=', '', strtr( base64_encode( $data ), '+/', '-_' ) );
    }

    function uuid() {
        return sprintf( '%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
            // 32 bits for "time_low"
            mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff ),
            // 16 bits for "time_mid"
            mt_rand( 0, 0xffff ),
            // 16 bits for "time_hi_and_version",
            // four most significant bits holds version number 4
            mt_rand( 0, 0x0fff ) | 0x4000,
            // 16 bits, 8 bits for "clk_seq_hi_res",
            // 8 bits for "clk_seq_low",
            // two most significant bits holds zero and one for variant DCE1.1
            mt_rand( 0, 0x3fff ) | 0x8000,
            // 48 bits for "node"
            mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff )
        );
    }
}
