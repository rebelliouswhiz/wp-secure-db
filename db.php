<?php
/**
 * Custom WordPress Database Class with X.509 SSL Support
 * 
 * Place this file as: wp-content/db.php
 * 
 * This drop-in extends wpdb to support X.509 client certificate authentication
 * for MySQL connections without modifying WordPress core files.
 */

// Require the standard WordPress database class
if ( file_exists( ABSPATH . WPINC . '/class-wpdb.php' ) ) {
    require_once( ABSPATH . WPINC . '/class-wpdb.php' );
} else {
    // Fallback for older WordPress versions
    require_once( ABSPATH . WPINC . '/wp-db.php' );
}

/**
 * Extended wpdb class with X.509 SSL certificate support
 */
class wpdb_ssl extends wpdb {
    
    /**
     * Constructor - ensures charset/collate are properly initialized
     */
    public function __construct( $dbuser, $dbpassword, $dbname, $dbhost ) {
        // Register the database credentials first
        $this->dbuser = $dbuser;
        $this->dbpassword = $dbpassword;
        $this->dbname = $dbname;
        $this->dbhost = $dbhost;

        // Set up initial charset/collate from DB_CHARSET and DB_COLLATE constants
        $this->init_charset();

        // Establish database connection (will use SSL if configured)
        $this->db_connect( false );
    }
    
    /**
     * Override db_connect to add SSL certificate support
     *
     * @param bool $allow_bail Optional. Allows the function to bail. Default true.
     * @return bool True with a successful connection, false on failure.
     */
    public function db_connect( $allow_bail = true ) {
        $this->is_mysql = true;

        // Suppress mysqli exceptions globally for compatibility
        $mysqli_driver = new mysqli_driver();
        $mysqli_driver->report_mode = MYSQLI_REPORT_OFF;

        $client_flags = defined( 'MYSQL_CLIENT_FLAGS' ) ? MYSQL_CLIENT_FLAGS : 0;
        
        // Check if we're using SSL
        $using_ssl = ( $client_flags & MYSQLI_CLIENT_SSL ) || 
                     defined( 'MYSQL_SSL_CA' ) || 
                     defined( 'MYSQL_SSL_CERT' ) || 
                     defined( 'MYSQL_SSL_KEY' );

        if ( $using_ssl && function_exists( 'mysqli_init' ) ) {
            // Initialize mysqli for SSL connection
            $this->dbh = mysqli_init();

            if ( ! $this->dbh ) {
                if ( $allow_bail ) {
                    wp_load_translations_early();
                    $this->bail( sprintf(
                        __( 'Error establishing a database connection: %s' ),
                        'mysqli_init failed'
                    ), 'db_connect_fail' );
                }
                return false;
            }

            // Set SSL options
            $ssl_key = defined( 'MYSQL_SSL_KEY' ) ? MYSQL_SSL_KEY : null;
            $ssl_cert = defined( 'MYSQL_SSL_CERT' ) ? MYSQL_SSL_CERT : null;
            $ssl_ca = defined( 'MYSQL_SSL_CA' ) ? MYSQL_SSL_CA : null;
            $ssl_capath = defined( 'MYSQL_SSL_CAPATH' ) ? MYSQL_SSL_CAPATH : null;
            $ssl_cipher = defined( 'MYSQL_SSL_CIPHER' ) ? MYSQL_SSL_CIPHER : null;

            // Verify SSL files exist (only log warnings, don't fail)
            if ( $ssl_ca && ! file_exists( $ssl_ca ) ) {
                error_log( "WordPress SSL DB: CA file not found at {$ssl_ca}" );
            }
            if ( $ssl_cert && ! file_exists( $ssl_cert ) ) {
                error_log( "WordPress SSL DB: Certificate file not found at {$ssl_cert}" );
            }
            if ( $ssl_key && ! file_exists( $ssl_key ) ) {
                error_log( "WordPress SSL DB: Key file not found at {$ssl_key}" );
            }

            // Apply SSL options
            mysqli_ssl_set(
                $this->dbh,
                $ssl_key,
                $ssl_cert,
                $ssl_ca,
                $ssl_capath,
                $ssl_cipher
            );

            // Set client flags for SSL
            $ssl_flag = MYSQLI_CLIENT_SSL;
            
            if ( defined( 'MYSQL_SSL_VERIFY_SERVER_CERT' ) && MYSQL_SSL_VERIFY_SERVER_CERT === false ) {
                $ssl_flag |= MYSQLI_CLIENT_SSL_DONT_VERIFY_SERVER_CERT;
            }

            $client_flags = $client_flags | $ssl_flag;

            // Parse host and port
            $host = $this->dbhost;
            $port = null;
            $socket = null;
            
            if ( strpos( $host, ':' ) !== false ) {
                list( $host, $port_or_socket ) = explode( ':', $host, 2 );
                if ( is_numeric( $port_or_socket ) ) {
                    $port = (int) $port_or_socket;
                } else {
                    $socket = $port_or_socket;
                }
            }
            
            // Attempt real connection
            $connection_result = mysqli_real_connect(
                $this->dbh,
                $host,
                $this->dbuser,
                $this->dbpassword,
                null,
                $port,
                $socket,
                $client_flags
            );

            if ( ! $connection_result ) {
                $error = mysqli_connect_error();
                if ( $allow_bail ) {
                    wp_load_translations_early();
                    $this->bail( sprintf(
                        __( 'Error establishing a database connection: %s' ),
                        $error
                    ), 'db_connect_fail' );
                }
                return false;
            }

            // Select database
            if ( ! mysqli_select_db( $this->dbh, $this->dbname ) ) {
                if ( $allow_bail ) {
                    wp_load_translations_early();
                    $this->bail( sprintf(
                        __( 'Can&#8217;t select database %s' ),
                        htmlspecialchars( $this->dbname, ENT_QUOTES )
                    ), 'db_select_fail' );
                }
                return false;
            }

            // Set charset using WordPress built-in method
            $this->set_charset( $this->dbh );
            
            $this->ready = true;
            $this->set_sql_mode();
            $this->select( $this->dbname, $this->dbh );

            return true;

        } else {
            // Fall back to standard connection (non-SSL)
            return parent::db_connect( $allow_bail );
        }
    }
    
    /**
     * Override init_charset to ensure proper charset/collate initialization
     * This matches WordPress core behavior
     */
    public function init_charset() {
        if ( function_exists( 'is_multisite' ) && is_multisite() ) {
            $this->charset = 'utf8';
            if ( defined( 'DB_COLLATE' ) && DB_COLLATE ) {
                $this->collate = DB_COLLATE;
            } else {
                $this->collate = 'utf8_general_ci';
            }
        } elseif ( defined( 'DB_COLLATE' ) ) {
            $this->collate = DB_COLLATE;
        }

        if ( defined( 'DB_CHARSET' ) ) {
            $this->charset = DB_CHARSET;
        }
    }
}

// Replace the global $wpdb with our extended class
$wpdb = new wpdb_ssl( DB_USER, DB_PASSWORD, DB_NAME, DB_HOST );