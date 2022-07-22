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

// Prevent loading outside of Wordpress
if ( ! defined( 'ABSPATH' ) ) exit;

if ( ! class_exists( 'wp_minecraft_auth' ) ) {
    final class WP_Minecraft_Auth_Controller {
        private static $instance;

        public $settings;
        public $session;
        public $oauth;

        public function __construct() { /* Do Nothing Here */ }

        public static function instance() {
            if ( ! isset( self::$instance ) && ! ( self::$instance instanceof WP_Minecraft_Auth_Controller ) ) {
                self::$instance = new WP_Minecraft_Auth_Controller;

                self::defineConstants();
                self::includes();

                self::$instance->settings = new WPMAuth_Settings( self::$instance );
                self::$instance->oauth = new WPMAuth_OAuth( self::$instance );
                self::$instance->session = new WPMAuth_SessionHandler( self::$instance );

                self::actions();

                register_activation_hook( dirname( __FILE__ ) . '/wp-minecraft-auth.php', array( __CLASS__, 'activate' ) );
                register_deactivation_hook( dirname( __FILE__ ) . '/wp-minecraft-auth.php', array( __CLASS__, 'deactivate' ) );

                self::$instance->write_log( 'WPMAUTH Instance Loaded' );
            }

            return self::$instance;
        }

        private static function defineConstants() {
            define( 'WPMAUTH_DIR_NAME', plugin_basename( dirname( __FILE__ ) ) );
			define( 'WPMAUTH_BASE_NAME', plugin_basename( __FILE__ ) );
            define( 'WPMAUTH_PATH', plugin_dir_path( __FILE__ ) );
            define( 'WPMAUTH_URL', plugin_dir_url( __FILE__ ) );
            define( 'WPMAUTH_VERSION', '1.0' );
        }

        private static function includes() {
            require_once WPMAUTH_PATH . 'includes/class.session.php';
            require_once WPMAUTH_PATH . 'includes/class.session_handler.php';
            require_once WPMAUTH_PATH . 'includes/class.oauth.php';
            require_once WPMAUTH_PATH . 'includes/class.settings.php';

            if ( is_admin() ) {
            
            }
        }

        public static function actions() {
            add_action( 'login_form', array( self::$instance, 'login_form_button' ) );
            add_action ( 'parse_request', array ( self::$instance, 'page_minecraft_auth' ), 10 );

            add_filter( 'wp_login_errors', array( self::$instance, 'login_errors' ), 10, 2 );
        }

        public static function activate() {
            WPMAuth_SessionHandler::createTable();
        }

        public static function deactivate() {
            WPMAuth_SessionHandler::removeTable();
        }

        public function page_minecraft_auth( $query ) {
            global $wp;
            require_once WPMAUTH_PATH . 'includes/class.microsoft.php';

            if ( $wp->request == 'minecraft-auth' ) {
                if ( isset( $_GET['action'] ) && $_GET['action'] == 'login' ) {
                    do_action( 'wp_minecraft_auth_set_cookies', true );

                    if ( isset( $_GET['getattributes'] ) && $_GET['getattributes'] == true ) {
                        setcookie( 'getattributes', true );
                    } else {
                        setcookie( 'getattributes', false );
                    }

                    if ( isset( $_GET['redirect_to'] ) && $this->session->hasSession() ) {
                        $this->session->redirect_to = sanitize_url( $_GET['redirect_to'] );
                    }

                    $ms = new WPMAuth_Microsoft( $this );
                    $token = $ms->get_token();
                    if ( $token ) {
                        $this->xboxlive_auth( $token );
                    }
                }

                if ( isset( $_GET[ 'code' ] ) && isset( $_GET[ 'state' ] ) ) {
                    $ms = new WPMAuth_Microsoft( $this );
                    
                    if ( $ms->authenticate_code( $_GET[ 'code' ], $_GET[ 'state' ] ) ) {
                        $this->xboxlive_auth( $ms->get_token() );
                    }
                }

                if ( isset( $_GET[ 'error' ] ) && isset( $_GET[ 'error_description' ] ) ) {
                    $this->add_error( $_GET[ 'error' ], $_GET[ 'error_description' ] );
                }
            }
        }

        public function xboxlive_auth( $token ) {
            require_once WPMAUTH_PATH . 'includes/class.xboxlive.php';
            $xbl = new WPMAuth_XboxLive( $this );

            if ( $xbl->authenticate_xbl( $token ) ) {
                $token = $xbl->xsts_token;
                $hash = $xbl->xsts_userhash;
                $this->minecraft_auth( $token, $hash );
            }
        }

        public function minecraft_auth( $token, $hash ) {
            require_once WPMAUTH_PATH . 'includes/class.xboxlive.php';
            $mc = new WPMAuth_Minecraft( $this );
            
            if ( $mc->authenticate( $token, $hash ) ) {

            }
        }

        public function user_login() {
            require_once WPMAUTH_PATH . 'includes/class.microsoft.php';
            require_once WPMAUTH_PATH . 'includes/class.xboxlive.php';
            require_once WPMAUTH_PATH . 'includes/class.user.php';

            $mc = new WPMAuth_Minecraft( $this );
            $ms = new WPMAuth_Microsoft( $this );
            $user = new WPMAuth_User;

            $ms_profile = $ms->get_profile();
            $mc_profile = $mc->get_profile();

            print_r( $ms_profile );
            print_r( $mc_profile );

            wp_die('Got Profiles');
        }

        public function mcAuth( $query ) {
            global $wp;
            if ( $wp->request == 'mc-auth' ) {
                do_action( 'wp_minecraft_auth_set_cookies', true );

                if ( isset( $_GET['action'] ) && $_GET['action'] == 'mc-login' ) {
                    
                    if ( isset( $_GET['getattributes'] ) && $_GET['getattributes'] == true ) {
                        setcookie( 'getattributes', true );
                    } else {
                        setcookie( 'getattributes', false );
                    }
                    
                    $this->oauth->authorizationEndpoint();
                }

                if ( isset( $_GET['code'] ) && isset( $_GET['state'] ) ) {
                    if ( wp_verify_nonce( $_GET['state'], 'mc-auth-login' ) == false ) {
                        wp_nonce_ays();
                    }

                    $oauth_response = $this->oauth->tokenEndpoint( $_GET['code'], 'authorization_code');

                    if ( array_key_exists( 'error', $oauth_response) ) {
                        $this->oauth->error( $oauth_response['error'], $oauth_response['error_description'] );
                    }

                    if ( ! array_key_exists( 'access_token', $oauth_response) ) {
                        $this->oauth->error( 'ms token invalid', 'The response received for the MS token was invalid.' );
                        exit();
                    }

                    $ms_token = array();
                    $ms_token['token_type'] = $oauth_response['token_type'];
                    $ms_token['expires'] = time() + $oauth_response['expires_in'];
                    $ms_token['scope'] = $oauth_response['scope'];
                    $ms_token['access_token'] = $oauth_response['access_token'];
                    $ms_token['refresh_token'] = $oauth_response['refresh_token'];
                    $this->session->ms_token = $ms_token;

                    echo 'MS Response:' . "/n";
                    print_r( $oauth_response );

                    $xbl_response = $this->oauth->xblEndpoint( $oauth_response['access_token'] );

                    $xbl_token = array();
                    $xbl_token['IssueInstant'] = $xbl_response['IssueInstant'];
                    $xbl_token['NotAfter'] = $xbl_response['NotAfter'];
                    $xbl_token['Token'] = $xbl_response['Token'];
                    $xbl_token['uhs'] = $xbl_response['DisplayClaims']['xui'][0]['uhs'];
                    $this->session->xml_token = $xbl_token;

                    $this->write_log ( $xbl_response );
                    echo "/n/n/n" . 'XBL Response:' . "/n";
                    print_r( $xbl_response );

                    // $xsts_response = $this->oauth->xstsEndpoint();

                    // $mc_response = $this->oauth->mcEndpoint();
                }

                header('Location: ' . home_url( '' ) );
            }
        }

        public function get_return_url() {
            return site_url( '/minecraft-auth' );
        }

        /**
         * Function loginFormButton
         *
         * Add login button for Minecraft on the login form.
         * @link https://codex.wordpress.org/Plugin_API/Action_Reference/login_form
         */
        public function login_form_button() {
            $return_url = '';
            if ( isset( $_GET['redirect_to'] ) ) {
                $return_url = '&return_to=' . urlencode( sanitize_url( $_GET['redirect_to'] ) );
            }
        ?>
            <a style="color:#FFF; width:100%; text-align:center; margin-bottom:1em;" class="button button-primary button-large" href="<?php echo $this->get_return_url() . '?action=login' . $return_url; ?>"><?php echo esc_html('Minecraft OAuth');?></a>
            <div style="clear:both;"></div>
        <?php
        }

        public function add_error( $code, $message, $extra = '', $recover = false ) {
            $this->write_log( 'Error Code: ' . $code . ' Message: ' . $message );
            
            if ( ! $this->session->hasSession() ) {
                $err = new WP_Error( $code, $message );
                wp_die( $err );
            }

            $errors = $this->session->get( 'errors', false );
            if ( $errors === false || ! is_array( $errors ) ) {
                $errors = array();
            }

            $errors[] = array(
                'code' => $code,
                'message' => $message,
                'extra' => $extra,
            );

            $this->session->errors = $errors;

            if ( ! $recover ) {
                header('Location: ' . wp_login_url() );
                exit();
            }
        }

        public function login_errors( $errors, $redirect_to ) {
            if ( ! $this->session->hasSession() ) return $errors;

            $errs = $this->session->get( 'errors', false );
            if ( $errs !== false && is_array( $errs ) ) {
                if ( is_wp_error( $errors ) ) {
                    foreach( $errs as $key => $value ) {
                        if ( is_array( $value ) ) {
                            $errors->add( $value['code'], $value['message'], $value['extra'] );
                        }
                    }

                    unset( $this->session->errors );
                }
            }

            return $errors;
        }

        public function write_log ( $log )  {
            if ( ( isset( $this->settings->debug ) && $this->settings->debug ) || ( defined( 'WP_DEBUG_LOG' ) && WP_DEBUG_LOG == true ) ) {
                $msg = '';
                if ( is_array( $log ) || is_object( $log ) ) {
                    $msg .= print_r( $log, true );
                } else {
                    $msg .= $log;
                }
                $msg .= "\n";
                error_log( $msg );
            }
        }

    }

    function wp_minecraft_auth() {
        global $wp_minecraft_auth_instance;

        $wp_minecraft_auth_instance = WP_Minecraft_Auth_Controller::instance();
        return $wp_minecraft_auth_instance;
    }
    
    wp_minecraft_auth();
}