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

use Automattic\Jetpack\Constants as Constants;

// Prevent loadinng outside of Wordpress
if ( ! defined( 'ABSPATH' ) ) exit;

class WPMAuth_SessionHandler extends WPMAuth_Session {
    private $_plugin;

    protected $_cookie;
    protected $_session_expiring;
    protected $_session_expiration;
    protected $_has_cookie = false;
    protected $_table;

    public function __construct( $instance ) {
        $this->_plugin = $instance;
        
        $this->_cookie = 'wp_minecraft_auth_' . COOKIEHASH;
        $this->_table = $GLOBALS['wpdb']->prefix . 'wp_minecraft_auth_sessions';

        $this->_plugin->write_log( 'WPMAuth Table: ' . $this->_table );
        $this->_plugin->write_log( 'WPMAuth Cookie: ' . $this->_cookie );

        add_action( 'init', array( $this, 'init') );
    }

    public function init() {
        $this->_plugin->write_log( 'WPMAuth Session Starting...' );

        $this->initSessionCookie();

        add_action( 'wp_minecraft_auth_set_cookies', array( $this, 'setUserSessionCookie' ), 10 );
        add_action( 'shutdown', array( $this, 'saveData' ), 20 );
        add_action( 'wp_logout', array( $this, 'destroySession' ) );

        $this->_plugin->write_log( 'WPMAuth Session Complete.' );
    }

    public function initSessionCookie() {
        $cookie = $this->getSessionCookie();

        if ( $cookie ) {
            $this->_user_id = $cookie[0];
            $this->_session_expiration = $cookie[1];
            $this->_session_expiring = $cookie[2];
            $this->_has_cookie = true;
            $this->_data = $this->getSessionData();

            if ( ! $this->isSessionCookieValid() ) {
                $this->destroySession();
                $this->setSessionExpiration();
            }

            if ( is_user_logged_in() && strval( get_current_user_id() ) !== $this->_user_id) {
                $guest_session_id = $this->_user_id;
                $this->_user_id = strval( get_current_user_id() );
                $this->_dirty = true;
                $this->saveData( $guest_session_id );
                $this->setUserSessionCookie( true );
            }

            if ( time() > $this->_session_expiring ) {
                $this->setSessionExpiration();
                $this->updateSessionTimestamp( $this->_user_id, $this->_session_expiration );
            }
        } else {
            $this->setSessionExpiration();
            $this->_user_id = $this->generateUserId();
            $this->_data = $this->getSessionData();
        }
    }

    private function isSessionCookieValid() {
        if ( time() > $this->_session_expiration ) {
            return false;
        }

        if ( ! is_user_logged_in() && ! $this->_isUserGuest( $this->_user_id ) ) {
            return false;
        }

        if ( is_user_logged_in() && ! $this->_isUserGuest( $this->_user_id ) && strval( get_current_user_id() ) != $this->_user_id ) {
            return false;
        }

        return true;
    }

    public function generateUserId() {
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

    public function setUserSessionCookie( $set ) {
        if ( $set ) {
            $to_hash = $this->_user_id . '|' . $this->_session_expiration;
            $cookie_hash = hash_hmac( 'md5', $to_hash, wp_hash( $to_hash ) );
            $cookie_value = $this->_user_id . '||' . $this->_session_expiration . '||' . $this->_session_expiring . '||' . $cookie_hash;
            $this->_has_cookie = true;

            if ( ! isset( $_COOKIE[ $this->_cookie ] ) || $_COOKIE[ $this->_cookie ] != $cookie_value ) {
                $this->_setCookie( $this->_cookie, $cookie_value, $this->_session_expiration );
            }
        }
    }

    public function getSessionCookie() {
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

    public function getSessionData() {
        return $this->hasSession() ? (array) $this->getSession( $this->_user_id, array() ) : array();
    }

    public function saveData( $old_session_key = 0 ) {
        if ( $this->_dirty && $this->hasSession() ) {
            global $wpdb;

            $wpdb->query(
                $wpdb->prepare(
                    "INSERT INTO {$this->_table} (`session_key`, `session_value`, `session_expiry`) VALUES (%s, %s, %d)
 					ON DUPLICATE KEY UPDATE `session_value` = VALUES(`session_value`), `session_expiry` = VALUES(`session_expiry`)",
					$this->_user_id,
					maybe_serialize( $this->_data ),
					$this->_session_expiration
                )
            );
        }

        $this->_dirty = false;
        if ( get_current_user_id() != $old_session_key && ! is_object( get_user_by( 'id', $old_session_key ) ) ) {
            $this->deleteSession( $old_session_key );
        }
    }

    public function destroySession() {
        $this->deleteSession( $this->_user_id );
        $this->forgetSession();
    }

    public function forgetSession() {
        $this->_setcookie( $this->_cookie, '', time() - YEAR_IN_SECONDS, $this->use_secure_cookie(), true );

        $this->_data = array();
        $this->_dirty = false;
        $this->_user_id = $this->generate_user_id();
    }

    public function setSessionExpiration() {
        $this->_session_expiring    = time() + intval( apply_filters( 'wpmauth_session_expiring', 60 * 60 * 47 ) ); // 47 Hours.
        $this->_session_expiration = time() + intval( apply_filters( 'wpmauth_session_expiration', 60 * 60 * 48 ) ); // 48 Hours.
    }

    /**
	 * Update the session expiry timestamp.
	 *
	 * @param string $user_id User ID.
	 * @param int    $timestamp Timestamp to expire the cookie.
	 */
	public function updateSessionTimestamp( $user_id, $timestamp ) {
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

    public function hasSession() {
		return isset( $_COOKIE[ $this->_cookie ] ) || $this->_has_cookie; // @codingStandardsIgnoreLine.
	}

    public function getSession( $user_id, $default = false ) {
        global $wpdb;

        if ( Constants::is_defined( 'WP_SETUP_CONFIG' ) ) {
            return false;
        }

        $value = $wpdb->get_var( $wpdb->prepare( "SELECT session_value FROM {$this->_table} WHERE session_key = %s", $user_id ) );

        if ( is_null( $value ) ) {
            $value = $default;
        }

        return maybe_unserialize( $value );
    }

    /**
	 * Delete the session from the cache and database.
	 *
	 * @param int $user_id User ID.
	 */
    public function deleteSession( $user_id ) {
        global $wpdb;

        $wpdb->delete(
            $this->_table,
            array(
                'session_key' => $user_id,
            )
        );
    }

    public function cleanupSessions() {
        global $wpdb;

        $wpdb->query( $wpdb->prepare( "DELETE FROM {$this->_table} WHERE session_expiry < %d", time() ) );
    }

    private function _isUserGuest( $user_id ) {
        $user_id = strval( $user_id );

        if ( empty( $user_id ) ) {
            return true;
        }

        if ( 't_' === substr( $user_id, 0, 2 ) ) {
            return true;
        }

        return false;
    }

    /**
     * Set a cookie - wrapper for setcookie using WP constants.
     *
     * @param  string  $name   Name of the cookie being set.
     * @param  string  $value  Value of the cookie.
     * @param  integer $expire Expiry of the cookie.
     */
    private function _setCookie( $name, $value, $expire = 0 ) {
        if ( ! apply_filters( 'wp_minecraft_auth_set_cookie_enabled', true, $name ,$value, $expire ) ) {
            return;
        }

        $secure = $this->_useSecureCookie();

        if ( ! headers_sent() ) {
            setcookie( $name, $value, $expire, COOKIEPATH ? COOKIEPATH : '/', COOKIE_DOMAIN, $secure, apply_filters( 'wp_minecraft_auth_cookie_httponly', true, $name, $value, $expire, $secure ) );
        } elseif ( Constants::is_true( 'WP_DEBUG' ) ) {
            headers_sent( $file, $line );
            trigger_error( "{$name} cookie cannot be set - headers already sent by {$file} on line {$line}", E_USER_NOTICE ); // @codingStandardsIgnoreLine
        }
    }

    private function _useSecureCookie() {
        return apply_filters( 'wp_minecraft_auth_use_secure_cookie', $this->_siteIsHttps() && is_ssl() );
    }

    private function _siteIsHttps() {
        return false !== strstr( get_option( 'home' ), 'https:' );
    }

    public static function createTable() {
        global $wpdb;

        $table_name = $wpdb->prefix . 'wp_minecraft_auth_sessions';

        $charset_collate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE $table_name (
            `session_id` bigint UNSIGNED NOT NULL AUTO_INCREMENT,
            `session_key` char(32) COLLATE utf8mb4_unicode_520_ci NOT NULL,
            `session_value` longtext COLLATE utf8mb4_unicode_520_ci NOT NULL,
            `session_expiry` bigint UNSIGNED NOT NULL,
            PRIMARY KEY (`session_id`),
            UNIQUE KEY `session_key` (`session_key`)
          ) $charset_collate;";
        
        require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );
        dbDelta( $sql );
    }

    public static function removeTable() {
        global $wpdb;

        $table_name = $wpdb->prefix . 'wp_minecraft_auth_sessions';
        $sql = "DROP TABLE IF EXISTS $table_name;";
        $wpdb->query( $sql );
    }
}