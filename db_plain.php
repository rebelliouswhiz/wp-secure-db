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
 * Extended wpdb class for specific charset and safe SQL modes
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

        // Enforce safe SQL mode after successful connection
        if ( $connected ) {
            $this->set_sql_mode();
        }

        return $connected;
    }
    
    /**
     * Set the SQL mode to a permissive default to fix Wordfence compatibility.
     * STRICT_TRANS_TABLES, NO_ZERO_IN_DATE, and NO_ZERO_DATE are removed.
     */
    public function set_sql_mode( $modes = array() ) {
        $safe_modes = array(
            'ERROR_FOR_DIVISION_BY_ZERO',
            'NO_ENGINE_SUBSTITUTION',
        );
        
        $modes_str = implode( ',', $safe_modes );
        
        // Use SESSION to avoid affecting other connections
        $this->query( "SET SESSION sql_mode = '{$modes_str}'" );
    }
}

// REMOVED: site_allow_strict_sql_modes function. 
// We no longer want to fight WordPress's built-in incompatible_sql_modes filter.

// Replace the global $wpdb with our extended class
$wpdb = new wpdb_plain( DB_USER, DB_PASSWORD, DB_NAME, DB_HOST );