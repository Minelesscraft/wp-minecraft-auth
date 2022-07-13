<?php
/*
Plugin Name: WP-Minecraft-Auth
Plugin URI: http://minelesscraft.com
Description: A Wordpress plugin to authenticate users via Microsoft Minecraft OAuth system.
Author: Visual Technology Solutions
Version: 1.0
License: GPLv2
Text Domain: wp-minecraft-auth
Domain Path: /languages
Author URI: https://www.vistecsol.com
WC requires at least: 5.0
WC tested up to: 6.0.0
*/

//namespace WPMinecraftAuth;

if ( ! defined( 'ABSPATH' ) ) exit;

define( 'WPMAUTH_INCLUDES', plugin_dir_path( __FILE__ ) . 'includes/' );
define( 'WPMAUTH_URL', plugin_dir_url( __FILE__ ) );
define( 'WPMAUTH_VERSION', '1.0' );

require_once WPMAUTH_INCLUDES . 'class.auth.php';

// // Require the helpers file, for use in :allthethings:
// require_once WMC_INCLUDES . 'helpers.php';
// Helpers\setup();

// // Handle everything order-related.
// require_once WMC_INCLUDES . 'order-manager.php';
// Orders\Manager\setup();

// // Handle everything order-cache related.
// require_once WMC_INCLUDES . 'order-cache-controller.php';
// Orders\Cache\setup();

// // Load the REST API
// require_once WMC_INCLUDES . 'rest-api.php';
// REST\setup();

// require_once WMC_INCLUDES . 'woocommerce-admin.php';
// WooCommerce\setup();

// // Fire an action after all is done.
// do_action( 'woominecraft_setup' );