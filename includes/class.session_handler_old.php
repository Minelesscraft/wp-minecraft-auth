<?php

/**
 * Class for Auth functions
 *
 * @package     wp-minecraft-auth
 * @subpackage  Session Handler
 * @copyright   Copyright (c) 2022, Visual Technology Solutions
 * @license     http://opensource.org/licenses/gpl-2.0.php GNU Public License
 * @since       1.0
 */

//namespace WPMinecraftAuth;
use Automattic\Jetpack\Constants;

// Prevent loadinng outside of Wordpress
if ( ! defined( 'ABSPATH' ) ) exit;

class WPMAuth_SessionHandler extends WPMAuth_Session {
    private $_plugin;

    private $_cookie;
    private $_session_expiring;
    private $_session_expiration;
    private $_has_cookie = false;
    private $_table;

    public function __construct() {
        $this->_plugin = wp_minecraft_auth();

        $this->_cookie = 'wp_minecraft_auth_' . COOKIEHASH;
        $this->_table = $GLOBALS['wpdb']->prefix . 'wp_minecraft_auth_sessions';

        //add_action( 'pre_get_posts', array ( $this, 'init' ), 10 );
        add_action( 'init', array( $this, 'init' ), 10 );
    }

    public static function setup() {
        global $wpdb;

        $table_name = $wpdb->prefix . 'wp_minecraft_auth_sessions';

        $charset_collate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE $table_name (
            `session_id` bigint UNSIGNED NOT NULL,
            `session_key` char(32) COLLATE utf8mb4_unicode_520_ci NOT NULL,
            `session_value` longtext COLLATE utf8mb4_unicode_520_ci NOT NULL,
            `session_expiry` bigint UNSIGNED NOT NULL
          ) $charset_collate;";
        
        require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );
        dbDelta( $sql );
    }

    public static function remove() {
        global $wpdb;

        $table_name = $wpdb->prefix . 'wp_minecraft_auth_sessions';
        $sql = "DROP TABLE IF EXISTS $table_name;";
        $wpdb->query( $sql );
    }

    public function init() {
        +8( 'Session Init' );
        $this->init_session_cookie();

        add_action( 'shutdown', array( $this, 'save_data' ), 20 );
        add_action( 'wp_logout', array( $this, 'destroy_session' ) );

        if ( ! is_user_logged_in() ) {
			add_filter( 'nonce_user_logged_out', array( $this, 'maybe_update_nonce_user_logged_out' ), 10, 2 );
		}
    }

    public function init_session_cookie() {
        $cookie = $this->get_session_cookie();

        if ( $cookie ) {
            $this->_user_id = $cookie[0];
            $this->_session_expiration = $cookie[1];
            $this->_session_expiring = $cookie[2];
            $this->_has_cookie = true;
            $this->_data = $this->get_session_data();

            if ( ! $this->is_session_cookie_valid() ) {
                $this->destroy_session();
                $this->set_session_expiration();
            }

            if ( is_user_logged_in() && strval( get_current_user_id() ) !== $this->_user_id ) {
                $guest_session_id = $this->_user_id;
                $this->_user_id = strval( get_current_user_id() );
                $this->_dirty = true;
                $this->save_data( $guest_session_id );
                $this->set_user_session_cookie( true );
            }

            if ( time() > $this->_session_expiring ) {
                $this->set_session_expiration();
                $this->update_session_timestamp( $this->_user_id, $this->_session_expiration );
            }
        } else {
            $this->set_session_expiration();
            $this->_user_id = $this->generate_user_id();
            $this->_data = $this->get_session_data();
        }
    }

    private function is_session_cookie_valid() {
        if ( time() > $this->_session_expiration ) {
            return false;
        }

        if ( ! is_user_logged_in() && ! $this->is_user_guest( $this->_user_id ) ) {
            return false;
        }

        if ( is_user_logged_in() && ! $this->is_user_guest( $this->_user_id ) && strval( get_current_user_id() ) != $this->_user_id ) {
            return false;
        }

        return true;
    }

    public function set_user_session_cookie( $set ) {
        if ( $set ) {
            $to_hash = $this->_user_id . '|' . $this->_session_expiration;
            $cookie_hash = hash_hmac( 'md5', $to_hash, wp_hash( $to_hash) );
            $cookie_value = $this->_user_id . '||' . $this->_session_expiration . '||' . $this->_session_expiring . '||' . $cookie_hash;
            $this->_has_cookie = true;

            if ( ! isset( $_COOKIE[ '$this->_cookie' ] ) || $_COOKIE[ $this->_cookie ] !== $cookie_value ) {
                $this->_setcookie( $this->_cookie, $cookie_value, $this->_session_expiration, $this->use_secure_cookie(), true );
            }
        }
    }

    private function use_secure_cookie() {
        return apply_filters( 'wpmauth_session_use_secure_cookie', $this->_site_is_https && is_ssl() );
    }

    public function has_session() {
        print_r( isset( $_COOKIE[ $this->_cookie ] ) );
        print_r( $this->_has_cookie );
        print_r( is_user_logged_in() );

        return isset( $_COOKIE[ $this->_cookie ] ) || $this->_has_cookie || is_user_logged_in();
    }

    public function set_session_expiration() {
        $this->_session_expiring    = time() + intval( apply_filters( 'wpmauth_session_expiring', 60 * 60 * 47 ) ); // 47 Hours.
        $this->_session_expiration = time() + intval( apply_filters( 'wpmauth_session_expiration', 60 * 60 * 48 ) ); // 48 Hours.
    }

    public function generate_user_id() {
        $user_id = '';

        if ( is_user_logged_in() ) {
            $user_id = strval( get_current_user_id() );
        }

        if ( empty( $user_id ) ) {
            require_once ABSPATH . 'wp-includes/class-phpass.php';
            $hasher = new PasswordHash( 8, false );
            $user_id = 't_' . substr( md5( $hasher->get_random_bytes( 32 ) ), 2 );
        }

        return $user_id;
    }

    private function is_user_guest( $user_id ) {
        $user_id = strval( $user_id );

        if ( empty( $user_id ) ) {
            return true;
        }

        if ( 't_' === substr( $user_id, 0, 2 ) ) {
            return true;
        }

        return false;
    }

    private function get_user_unique_id() {
        $user_id = '';

        if ( $this->has_session() && $this->_user_id ) {
            $user_id = $this->_user_id;
        } elseif (is_user_logged_in() ) {
            $user_id = (string) get_current_user_id();
        }

        return $user_id;
    }

    public function get_session_cookie() {
        $cookie_value = isset( $_COOKIE[ $this->_cookie ] ) ? wp_unslash( $_COOKIE[ $this->_cookie ] ) : false;

        if ( empty( $cookie_value ) || ! is_string( $cookie_value ) ) {
            return false;
        }

        list( $user_id, $session_expiration, $session_expiring, $cookie_hash ) = explode( '||', $cookie_value );

        if ( empty( $user_id ) ) {
            return false;
        }

        $to_hash = $user_id . '|' . $session_expiration;
        $hash = hash_hmac( 'md5', $to_hash, wp_hash( $to_hash ) );

        if ( empty( $cookie_hash ) || ! hash_equals( $hash, $cookie_hash ) ) {
            return false;
        }

        return array( $user_id, $session_expiration, $session_expiring, $cookie_hash );
    }

    public function get_session_data() {
        return $this->has_session() ? (array) $this->get_session( $this->_user_id, array() ) : array();
    }

    public function save_data( $old_session_key = 0 ) {
        if ( $this->_dirty && $this->has_session() ) {
            global $wpdb;

            $wpdb->query(
                $wpdb->prepare(
                    "INSERT INTO {$wpdb->prefix}wp_minecraft_auth_sessions (`session_key`, `session_value`, `session_expiry`) VALUES (%s, %s, %d)
 					ON DUPLICATE KEY UPDATE `session_value` = VALUES(`session_value`), `session_expiry` = VALUES(`session_expiry`)",
					$this->_user_id,
					maybe_serialize( $this->_data ),
					$this->_session_expiration
                )
            );
        }

        $this->_dirty = false;
        if ( get_current_user_id() != $old_session_key && ! is_object( get_user_by( 'id', $old_session_key ) ) ) {
            $this->delete_session( $old_session_key );
        }
    }

    public function destroy_session() {
        $this->delete_session( $this->_user_id );
        $this->forget_session();
    }

    public function forget_session() {
        $this->_setcookie( $this->_cookie, '', time() - YEAR_IN_SECONDS, $this->use_secure_cookie(), true );

        $this->_data = array();
        $this->_dirty = false;
        $this->_user_id = $this->generate_user_id();
    }

    public function maybe_update_nonce_user_logged_out( $uid, $action ) {
		if ( $this->_starts_with( $action, 'wpmauth' ) ) {
			return $this->has_session() && $this->_user_id ? $this->_user_id : $uid;
		}

		return $uid;
	}

    public function cleanup_session() {
        global $wpdb;

        $wpdb->query( $wpdb->prepare( "DELETE FROM $this->_table WHERE session_expiry < %d", time() ) );
    }

    public function get_session( $user_id, $default = false ) {
        global $wpdb;

        if ( Constants::is_defined( 'WP_SETUP_CONFIG' ) ) {
            return false;
        }

        $value = $wpdb->get_var( $wpdb->prepare( "SELECT session_value FROM $this->_table WHERE session_key = %s", $user_id ) );

        if ( is_null( $value ) ) {
            $value = $default;
        }

        return maybe_unserialize( $value );
    }

    public function delete_session( $user_id ) {
        global $wpdb;

        $wpdb->delete(
            $this->_table,
            array(
                'session_key' => $user_id,
            )
        );
    }

    public function update_session_timestamp( $user_id, $timestamp ) {
        global $wpdb;

        $wpdb->update(
            $this->_table,
            array(
                'session_expiry' => $timestamp,
            ),
            array(
                'session_key' => $user_id,
            ),
            array(
                '%d',
            )
        );
    }

    private function _setcookie( $name, $value, $expire = 0, $secure = false, $httponly = false ) {
        if ( ! headers_sent() ) {
            setcookie( $name, $value, $expire, COOKIEPATH ? COOKIEPATH : '/', COOKIE_DOMAIN, $secure, apply_filters( 'wpmauth_cookie_httponly', $httponly, $name, $value, $expire, $secure ) );
        } elseif ( Constants::is_true( 'WP_DEBUG' ) ) {
            headers_sent( $file, $line );
            trigger_error( "{$name} cookie cannot be set - headers already sent by {$file} on line {$line}", E_USER_NOTICE ); // @codingStandardsIgnoreLine
        }
    }

    private function _starts_with( $string, $starts_with, $case_sensitive = true ) {
        $len = strlen( $starts_with );
		if ( $len > strlen( $string ) ) {
			return false;
		}

		$string = substr( $string, 0, $len );

		if ( $case_sensitive ) {
			return strcmp( $string, $starts_with ) === 0;
		}

		return strcasecmp( $string, $starts_with ) === 0;
    }

    private function _site_is_https() {
        return false !== strstr( get_option( 'home' ), 'https:' );
    }

}