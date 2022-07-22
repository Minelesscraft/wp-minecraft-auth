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

class WPMAuth_SubArray {
    protected $_data;
    protected $_dirty;

    public function __construct( &$array, &$dirty ) {
        $this->_data = $array;
        $this->_dirty = $dirty;
    }

    public function __set( $key, $value ) {
        if ( $value !== $this->_data[ $key ] ) {
            $this->_data[ sanitize_key( $key ) ] = $value;
            $this->_dirty = true;
        }
    }

    public function __get( $key ) {
        if ( ! array_key_exists( $key, $this->_data ) ) {
            return null;
        }

        if ( is_array( $this->_data[ $key ] ) ) {
            return new self( $this->_data[ $key ], $this->_dirty );
        } else {
            return $this->_data[ $key ];
        }
    }
}