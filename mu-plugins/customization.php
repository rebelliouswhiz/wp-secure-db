<?php
/**
 * Plugin Name: Customization
 * Description: Custom configurations for email notifications and SQL schema fixes
 * Version: 2.3.1
 */

if (!defined('ABSPATH')) {
    exit;
}

// Disable update emails
add_filter('auto_core_update_send_email', '__return_false');
add_filter('auto_plugin_update_send_email', '__return_false');
add_filter('auto_theme_update_send_email', '__return_false');

/**
 * Intercept database queries to prevent zero dates in table schemas and data
 * Runs at priority 1 to execute early in the query chain
 */
add_filter('query', 'site_prevent_zero_dates_in_queries', 1);

function site_prevent_zero_dates_in_queries($query) {
    if (!is_string($query) || empty($query)) {
        return $query;
    }

    // Get query type efficiently
    $query_upper = strtoupper(ltrim($query));

    // Handle CREATE TABLE and ALTER TABLE - modify schema definitions
    if (strpos($query_upper, 'CREATE TABLE') === 0 || strpos($query_upper, 'ALTER TABLE') === 0) {

        // Match datetime/timestamp with optional precision: datetime, datetime(0), datetime(6), etc.
        // Replace NOT NULL DEFAULT '0000-00-00 00:00:00' with NULL DEFAULT NULL
        $query = preg_replace(
            '/\\b(datetime|timestamp)(\\\(\\d+\\\))?\\s+NOT\\s+NULL\\s+DEFAULT\\s+([\'"])0000-00-00 00:00:00\\3/i',
            '$1$2 NULL DEFAULT NULL',
            $query
        );

        // Replace DEFAULT '0000-00-00 00:00:00' (without NOT NULL) with DEFAULT NULL
        $query = preg_replace(
            '/\\b(datetime|timestamp)(\\\(\\d+\\\))?\\s+DEFAULT\\s+([\'"])0000-00-00 00:00:00\\3/i',
            '$1$2 DEFAULT NULL',
            $query
        );

        // Handle DATE columns (without time component)
        $query = preg_replace(
            '/\\bdate\\s+NOT\\s+NULL\\s+DEFAULT\\s+([\'"])0000-00-00\\1/i',
            'date NULL DEFAULT NULL',
            $query
        );

        $query = preg_replace(
            '/\\bdate\\s+DEFAULT\\s+([\'"])0000-00-00\\1/i',
            'date DEFAULT NULL',
            $query
        );

        // Handle datetime/timestamp NOT NULL with NO DEFAULT at all (e.g. WordFence attackLogTime)
        // Negative lookaheads prevent clobbering columns that already have a DEFAULT or ON UPDATE clause
        $query = preg_replace(
            '/\\b(datetime|timestamp)(\\\(\\d+\\\))?\\s+NOT\\s+NULL(?!\\s+DEFAULT)(?!\\s+ON\\s+UPDATE)(?!\\s+AUTO_INCREMENT)/i',
            '$1$2 NULL DEFAULT NULL',
            $query
        );

        // Handle DATE NOT NULL with no DEFAULT at all
        $query = preg_replace(
            '/\\bdate\\s+NOT\\s+NULL(?!\\s+DEFAULT)/i',
            'date NULL DEFAULT NULL',
            $query
        );

    }

    // Handle INSERT, UPDATE, REPLACE - convert zero dates in VALUES/SET clauses only
    elseif (strpos($query_upper, 'INSERT') === 0 ||
            strpos($query_upper, 'UPDATE') === 0 ||
            strpos($query_upper, 'REPLACE') === 0) {

        // Replace zero datetime values that appear as complete SQL values
        // Lookahead ensures we only match standalone values, not text content
        $query = preg_replace(
            '/([\'"])0000-00-00 00:00:00\\1(?=[,)\s]|$)/i',
            'NULL',
            $query
        );

        // Also handle DATE values (without time)
        $query = preg_replace(
            '/([\'"])0000-00-00\\1(?=[,)\s]|$)/i',
            'NULL',
            $query
        );
    }

    return $query;
}