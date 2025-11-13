<?php
/**
 * Custom WordPress Database Class with X.509 SSL Support
 * 
 * Place this file as: wp-content/db.php
 * 
 * This drop-in extends wpdb to support X.509 client certificate authentication
 * for MySQL connections without modifying WordPress core files.
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
    die( 'Direct access not permitted.' );
}

// Require the standard WordPress database class
if ( file_exists( ABSPATH . WPINC . '/class-wpdb.php' ) ) {
    require_once( ABSPATH . WPINC . '/class-wpdb.php' );
} else {
    // Fallback for older WordPress versions (pre-6.1)
    require_once( ABSPATH . WPINC . '/wp-db.php' );
}

/**
 * Extended wpdb class with X.509 SSL certificate support
 * 
 * @since 1.0.0
 */
class wpdb_ssl extends wpdb {
    
    /**
     * Maximum number of connection retry attempts
     * 
     * @var int
     */
    private $max_retries = 3;
    
    /**
     * Current retry attempt counter
     * 
     * @var int
     */
    private $retry_count = 0;
    
    /**
     * Constructor - ensures charset/collate are properly initialized
     * 
     * @param string $dbuser     Database username
     * @param string $dbpassword Database password
     * @param string $dbname     Database name
     * @param string $dbhost     Database host
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
     * Override db_connect to add SSL certificate support with retry logic
     *
     * @param bool $allow_bail Optional. Allows the function to bail. Default true.
     * @return bool True with a successful connection, false on failure.
     */
    public function db_connect( $allow_bail = true ) {
        $this->is_mysql = true;

        // Suppress mysqli exceptions globally for compatibility with poorly coded plugins
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
                $error_msg = 'mysqli_init failed';
                $this->log_error( $error_msg );
                
                if ( $allow_bail ) {
                    wp_load_translations_early();
                    $this->bail( sprintf(
                        __( 'Error establishing a database connection: %s' ),
                        $error_msg
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

            // Verify SSL files exist before attempting connection
            if ( ! $this->verify_ssl_files( $ssl_ca, $ssl_cert, $ssl_key ) && $allow_bail ) {
                wp_load_translations_early();
                $this->bail(
                    __( 'Error establishing a database connection: SSL certificate files not found or not readable.' ),
                    'db_ssl_files_missing'
                );
                return false;
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
            
            // Handle SSL certificate verification
            if ( defined( 'MYSQL_SSL_VERIFY_SERVER_CERT' ) && MYSQL_SSL_VERIFY_SERVER_CERT === false ) {
                // Disable server certificate verification (not recommended for production)
                $ssl_flag |= MYSQLI_CLIENT_SSL_DONT_VERIFY_SERVER_CERT;
                $this->log_error( 'WARNING: Server certificate verification disabled. This is not recommended for production environments.' );
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
            
            // Attempt real connection with retry logic
            $connection_result = $this->attempt_connection(
                $host,
                $port,
                $socket,
                $client_flags,
                $allow_bail
            );

            if ( ! $connection_result ) {
                return false;
            }

            // Select database
            if ( ! mysqli_select_db( $this->dbh, $this->dbname ) ) {
                $error_msg = sprintf( 'Cannot select database: %s', $this->dbname );
                $this->log_error( $error_msg );
                
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
     * Attempt database connection with retry logic
     * 
     * @param string $host         Database host
     * @param int    $port         Database port
     * @param string $socket       Database socket
     * @param int    $client_flags Connection flags
     * @param bool   $allow_bail   Whether to bail on failure
     * @return bool True on success, false on failure
     */
    private function attempt_connection( $host, $port, $socket, $client_flags, $allow_bail ) {
        for ( $attempt = 0; $attempt <= $this->max_retries; $attempt++ ) {
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

            if ( $connection_result ) {
                if ( $attempt > 0 ) {
                    $this->log_error( sprintf( 'Database connection succeeded on retry attempt %d', $attempt ) );
                }
                return true;
            }

            // Connection failed
            $error = mysqli_connect_error();
            $this->log_error( sprintf(
                'Database connection attempt %d failed: %s',
                $attempt + 1,
                $error
            ) );

            // If not the last attempt, wait before retrying
            if ( $attempt < $this->max_retries ) {
                usleep( 100000 * ( $attempt + 1 ) ); // Progressive backoff: 100ms, 200ms, 300ms
            }
        }

        // All retry attempts exhausted
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
    
    /**
     * Verify SSL certificate files exist and are readable
     * 
     * @param string|null $ssl_ca   CA file path
     * @param string|null $ssl_cert Certificate file path
     * @param string|null $ssl_key  Key file path
     * @return bool True if all files are valid, false otherwise
     */
    private function verify_ssl_files( $ssl_ca, $ssl_cert, $ssl_key ) {
        $all_valid = true;

        if ( $ssl_ca && ! $this->is_file_readable( $ssl_ca ) ) {
            $this->log_error( sprintf( 'SSL CA file not found or not readable: %s', $ssl_ca ) );
            $all_valid = false;
        }
        
        if ( $ssl_cert && ! $this->is_file_readable( $ssl_cert ) ) {
            $this->log_error( sprintf( 'SSL certificate file not found or not readable: %s', $ssl_cert ) );
            $all_valid = false;
        }
        
        if ( $ssl_key && ! $this->is_file_readable( $ssl_key ) ) {
            $this->log_error( sprintf( 'SSL key file not found or not readable: %s', $ssl_key ) );
            $all_valid = false;
        }

        return $all_valid;
    }
    
    /**
     * Check if a file exists and is readable
     * 
     * @param string $filepath File path to check
     * @return bool True if file exists and is readable
     */
    private function is_file_readable( $filepath ) {
        return file_exists( $filepath ) && is_readable( $filepath );
    }
    
    /**
     * Log error messages to PHP error log
     * 
     * @param string $message Error message to log
     */
    private function log_error( $message ) {
        if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
            error_log( sprintf( '[WordPress SSL DB] %s', $message ) );
        }
    }
    
    /**
     * Set the SQL mode to a strict and secure default.
     *
     * This overrides the parent method to enforce a specific set of SQL modes,
     * ensuring consistent and strict database behavior.
     *
     * @param array $modes Ignored. The modes are hardcoded for security.
     */
    public function set_sql_mode( $modes = array() ) {
        $strict_modes = array(
            'STRICT_TRANS_TABLES',
            'NO_ZERO_IN_DATE',
            'NO_ZERO_DATE',
            'ERROR_FOR_DIVISION_BY_ZERO',
            'NO_ENGINE_SUBSTITUTION',
        );
        
        $modes_str = implode( ',', $strict_modes );
        
        // Use SESSION to avoid affecting other connections
        $this->query( "SET SESSION sql_mode = '{$modes_str}'" );
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

/**
 * Allow strict SQL modes for modern database environments.
 *
 * By default, WordPress disables certain strict SQL modes. This function removes
 * specific modes from the "incompatible" list, allowing them to be used.
 *
 * @param array $modes List of incompatible SQL modes.
 * @return array Modified list of incompatible modes.
 */
function site_allow_strict_sql_modes($modes) {
    if (!is_array($modes)) {
        return array();
    }
    
    // Remove these from the "incompatible" list so WordPress keeps them
    $allowed_strict_modes = array(
        'NO_ZERO_DATE',
        'STRICT_TRANS_TABLES',
        'NO_ZERO_IN_DATE',
        'ERROR_FOR_DIVISION_BY_ZERO'
    );
    
    return array_diff($modes, $allowed_strict_modes);
}
add_filter('incompatible_sql_modes', 'site_allow_strict_sql_modes');

// Replace the global $wpdb with our extended class
$wpdb = new wpdb_ssl( DB_USER, DB_PASSWORD, DB_NAME, DB_HOST );