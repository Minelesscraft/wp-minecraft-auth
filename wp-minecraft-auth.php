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

namespace WPMinecraftAuth;

// Prevent loadinng outside of Wordpress
if ( ! defined( 'ABSPATH' ) ) exit;

define( 'WPMAUTH_INCLUDES', plugin_dir_path( __FILE__ ) . 'includes/' );
define( 'WPMAUTH_URL', plugin_dir_url( __FILE__ ) );
define( 'WPMAUTH_VERSION', '1.0' );

require_once WPMAUTH_INCLUDES . 'class.settings.php';
require_once WPMAUTH_INCLUDES . 'class.auth.php';

