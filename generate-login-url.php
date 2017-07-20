<?php
/*
Plugin Name: Generate Auto-login URL
Description: A plugin to generate a login URL, which a user can use to automatically log into the Wordpress website.
Author: Rudolph Koegelenberg
Author URI: http://www.rudolphk.co.za
Version: 1.0
*/

class GenerateAutoLoginSettingsPage
{
    /**
     * Holds the values to be used in the fields callbacks
     */
    private $options;

    /**
     * Start up
     */
    public function __construct()
    {
        add_action( 'admin_menu', array( $this, 'add_plugin_settings_page' ) );
        add_action( 'admin_menu', array( $this, 'add_plugin_page' ) );
        add_action( 'admin_init', array( $this, 'page_init' ) );
        add_action( 'init', array( $this, 'auto_login' ) );
        register_activation_hook( __FILE__, array( $this, 'install' ) );
        add_filter( 'plugin_action_links_' . plugin_basename(__FILE__), array( $this, 'add_action_links' ) );
    }
    
    public function add_action_links ( $links ) {
         $mylinks = array(
            '<a href="' . admin_url( 'options-general.php?page=galu-admin') . '">Settings</a>',
         );
        return array_merge( $links, $mylinks );
    }
    
    public function install(){
        $default = array(
            'galu_encryption_key'    => 'dkdkdkd',
            'galu_encryption_salt'   => 'dkdkdkd'
        );
        update_option( 'galu_encryption_keys', $default );
    }
    
    public function auto_login(){
        if( isset($_GET['username']) and $_GET['pass'] ) {
            $user = get_user_by('login', $_GET['username']);
        
            if ( $user && wp_check_password($this->encrypt_decrypt('decrypt', $_GET['pass']), $user->data->user_pass, $user->ID) ) {
                wp_set_current_user($user->ID, $user->user_login);
                wp_set_auth_cookie($user->ID, true);
                do_action('wp_login', $user->user_login);
                wp_redirect('/');
                exit;
            }
        
            wp_redirect('/');
            exit;
        }
    }
    
    /**
     * Add options page
     */
    public function add_plugin_page()
    {
        // This page will be under "Settings"
        add_users_page( 'Generate Auto-login URL', 'Generate Auto-login URL', 'manage_options', 'galu-admin-url', array( $this, 'create_admin_page' ));
    }
    
    public function encrypt_decrypt($action, $string) {
        $output = false;
    
        $encrypt_method = "AES-256-CBC";
        $options = get_option( 'galu_encryption_keys' );
    
        // hash
        $key = hash('sha256', $options->galu_encryption_key);
        
        // iv - encrypt method AES-256-CBC expects 16 bytes - else you will get a warning
        $iv = substr(hash('sha256', $options->galu_encryption_salt), 0, 16);
    
        if( $action == 'encrypt' ) {
            $output = openssl_encrypt($string, $encrypt_method, $key, 0, $iv);
            $output = base64_encode($output);
        }
        else if( $action == 'decrypt' ){
            $output = openssl_decrypt(base64_decode($string), $encrypt_method, $key, 0, $iv);
        }
    
        return $output;
    }

    /**
     * Options page callback
     */
    public function create_admin_page()
    {
        ?>
        <div class="wrap">
            <h1>Generate Auto-login URL</h1>
            <form method="post" action="">
                <table class="form-table">
                    <tbody>
                        <tr><th scope="row">Username</th><td><input type="text" name="username" value="<?php if (isset($_POST['username'])) echo $_POST['username'] ?>" /></td></tr>
                        <tr><th scope="row">Password</th><td><input type="text" name="password" value="<?php if (isset($_POST['password'])) echo $_POST['password'] ?>" /></td></tr>
                    </tbody>
                </table>
                <input type="hidden" name="action" value="generate" />
                <input type="submit" class="button-primary" value="Generate URL!" />
            </form>
        </div>
        <br/>
        <?php
        if ( !empty($_POST['action']) && $_POST['action'] == 'generate'){
            echo '<strong>Generated URL:</strong> ' . get_site_url() . '/?username=' . $_POST['username'] . '&pass=' . $this->encrypt_decrypt('encrypt', $_POST['password']); 
        }
    }

    /**
     * Add options page
     */
    public function add_plugin_settings_page()
    {
        // This page will be under "Settings"
        add_options_page(
            'Generate Auto-login Settings', 
            'Generate Auto-login Settings', 
            'manage_options', 
            'galu-admin', 
            array( $this, 'create_admin_settings_page' )
        );
    }

    /**
     * Options page callback
     */
    public function create_admin_settings_page()
    {
        // Set class property
        $this->options = get_option( 'galu_encryption_keys' );
        ?>
        <div class="wrap">
            <h1>Generate Auto-login Settings</h1>
            <form method="post" action="options.php">
            <?php
                // This prints out all hidden setting fields
                settings_fields( 'my_option_group' );
                do_settings_sections( 'galu-admin' );
                submit_button();
            ?>
            </form>
        </div>
        <?php
    }

    /**
     * Register and add settings
     */
    public function page_init()
    {        
        register_setting(
            'my_option_group', // Option group
            'galu_encryption_keys', // Option name
            array( $this, 'sanitize' ) // Sanitize
        );

        add_settings_section(
            'encryption_keys', // ID
            'Encryption Keys', // Title
            array( $this, 'print_section_info' ), // Callback
            'galu-admin' // Page
        );  

        add_settings_field(
            'galu_encryption_key', // ID
            'Encryption Key', // Title 
            array( $this, 'encryption_key_callback' ), // Callback
            'galu-admin', // Page
            'encryption_keys' // Section           
        );      

        add_settings_field(
            'galu_encryption_salt', 
            'Encryption Salt', 
            array( $this, 'encryption_salt_callback' ), 
            'galu-admin', 
            'encryption_keys'
        );      
    }

    /**
     * Sanitize each setting field as needed
     *
     * @param array $input Contains all settings fields as array keys
     */
    public function sanitize( $input )
    {
        $new_input = array();
        if( isset( $input['galu_encryption_key'] ) )
            $new_input['galu_encryption_key'] = sanitize_text_field( $input['galu_encryption_key'] );

        if( isset( $input['galu_encryption_salt'] ) )
            $new_input['galu_encryption_salt'] = sanitize_text_field( $input['galu_encryption_salt'] );

        return $new_input;
    }

    /** 
     * Print the Section text
     */
    public function print_section_info()
    {
        print 'Enter your settings below:';
    }

    /** 
     * Get the settings option array and print one of its values
     */
    public function encryption_key_callback()
    {
        printf(
            '<input type="text" id="galu_encryption_key" name="galu_encryption_keys[galu_encryption_key]" value="%s" />',
            isset( $this->options['galu_encryption_key'] ) ? esc_attr( $this->options['galu_encryption_key']) : ''
        );
    }

    /** 
     * Get the settings option array and print one of its values
     */
    public function encryption_salt_callback()
    {
        printf(
            '<input type="text" id="galu_encryption_salt" name="galu_encryption_keys[galu_encryption_salt]" value="%s" />',
            isset( $this->options['galu_encryption_salt'] ) ? esc_attr( $this->options['galu_encryption_salt']) : ''
        );
    }
}

if( is_admin() )
    $my_settings_page = new GenerateAutoLoginSettingsPage();