<?php
/**
 * Custom WordPress Database Class (Plain - No SSL)
 * 
 * This drop-in extends wpdb to enforce specific Charset, Collate and SQL Modes
 * without the SSL connection overhead.
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
    die( 'Direct access not permitted.' );
}

// Require the standard WordPress database class
if ( file_exists( ABSPATH . WPINC . '/class-wpdb.php' ) ) {
    require_once( ABSPATH . WPINC . '/class-wpdb.php' );
} else {
    // Fallback for older WordPress versions
    require_once( ABSPATH . WPINC . '/wp-db.php' );
}

/**
 * Extended wpdb class for strict SQL modes and specific charset
 */
class wpdb_plain extends wpdb {
    
    /**
     * Enforce specific Charset and Collate always
     */
    public function init_charset() {
        $this->charset = 'utf8mb4';
        $this->collate = 'utf8mb4_0900_ai_ci';
    }
    
    /**
     * Connect to the database and apply SQL modes
     */
    public function db_connect( $allow_bail = true ) {
        // Use standard WordPress connection logic
        $connected = parent::db_connect( $allow_bail );

        // Enforce strict SQL mode after successful connection
        if ( $connected ) {
            $this->set_sql_mode();
        }

        return $connected;
    }
    
    /**
     * Set the SQL mode to a strict and secure default.
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
}

/**
 * Allow strict SQL modes for modern database environments.
 */
function site_allow_strict_sql_modes($modes) {
    if (!is_array($modes)) {
        return array();
    }
    
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
$wpdb = new wpdb_plain( DB_USER, DB_PASSWORD, DB_NAME, DB_HOST );
