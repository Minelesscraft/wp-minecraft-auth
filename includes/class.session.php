<?php

/**
 * Class for Auth functions
 *
 * @package     wp-minecraft-auth
 * @subpackage  Session
 * @copyright   Copyright (c) 2022, Visual Technology Solutions
 * @license     http://opensource.org/licenses/gpl-2.0.php GNU Public License
 * @since       1.0
 */

 // Prevent loadinng outside of Wordpress
if ( ! defined( 'ABSPATH' ) ) exit;

require_once WPMAUTH_PATH . 'includes/class.sub_array.php';

abstract class WPMAuth_Session {

    protected $_user_id;
    protected $_data = array();
    protected $_dirty = false;

    
    public function init() {} // Extended by child classes

    public function cleanup_sessions() {} // Extended by child classes

    public function __get( $key ) {
        if ( ! array_key_exists( $key, $this->_data ) ) {
            return null;
        }

        if ( is_array( $this->_data[ $key ] ) ) {
            return new WPMAuth_SubArray( $this->_data[ $key ], $this->_dirty );
        } else {
            return $this->_data[ $key ];
        }
    }

    public function __set( $key, $value ) {
        if ( array_key_exists( $key, $this->_data ) && $value === $this->_data[ $key ] ) {
            return;
        }
        $this->_data[ sanitize_key( $key ) ] = $value;
        $this->_dirty = true;
    }

    public function __isset( $key ) {
        return isset( $this->_data[ sanitize_title( $key ) ] );
    }

    public function __unset( $key ) {
        if ( isset( $this->_data[ $key ] ) ) {
            unset( $this->_data[ $key ] );
            $this->_dirty = true;
        }
    }

    public function get( $key, $default = null ) {
        $key = sanitize_key( $key );
        return isset( $this->_data[ $key ] ) ? maybe_unserialize( $this->_data[ $key ] ) : $default;
    }

    public function set( $key, $value ) {
        if ( $value !== $this->get( $key ) ) {
            $this->_data[ sanitize_key( $key ) ] = maybe_serialize( $value );
            $this->_dirty = true;
        }
    }

    public function get_user_id() {
		return $this->_user_id;
	}

}