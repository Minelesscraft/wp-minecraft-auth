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

class wpmauth_oauth {
    function error( $message ) {
        $result = new WP_Error ( 'Minecraft Auth', $message );
        return $result;
    }

    function generate( $data ) {
        if ( _OAUTH_METHOD == 'certificate' ) {
            $cert = file_get_contents( _OAUTH_AUTH_CERT );
            $certKey = oppenssl_pkey_get_private( file_get_contents( _OAUTH_AUTH_CERTKEY ) );
            $certHash = openssl_x509_fingerprint( $cert );
            $certHash = base64_encode ( hex2bin( $certHash ) );
            $caHeader = json_encode( array( 'alg' => 'RS256', 'typ' => 'JWT', 'x5t' => $certHash ) );
            $caPayload = json_encode( array( 'aud' => 'https://login.microsoftonline.com/' . _OAUTH_TENANTID . '/v2.0',
                                             'exp' => date( 'U', strtotime( '+10 minute' ) ),
                                             'iss' => _OAUTH_CLIENTID,
                                             'jti' => $this->uuid(),
                                             'nbf' => date( 'U' ),
                                             'sub' => _OAUTH_CLIEENTID ) );
            $caSignature = '';
        }
    }

    function post( $endpoint, $data ) {
        return wp_remote_post( 'https://login.microsoftonline.com/' . _OAUTH_TENANTID . '/oauth2/v2.0/' . $endpoint );

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
