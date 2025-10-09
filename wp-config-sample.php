/** Database username */
define( 'DB_USER', 'username_here' );

/** Database password */
define( 'DB_PASSWORD', 'password_here' );

/** Database hostname */
define( 'DB_HOST', 'host:port' );

/** Database charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8mb4' );

/** The database collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', 'utf8mb4_0900_ai_ci' );

// ** SSL Database Connection Settings ** //
/** Enable SSL database connection. */
define( 'MYSQL_CLIENT_FLAGS', MYSQLI_CLIENT_SSL );

/** Path to SSL key file. */
define( 'MYSQL_SSL_KEY', '/path/to/your/client-key.pem' );

/** Path to SSL certificate file. */
define( 'MYSQL_SSL_CERT', '/path/to/your/client-cert.pem' );

/** Path to SSL CA certificate file. */
define( 'MYSQL_SSL_CA', '/path/to/your/ca-cert.pem' );

/** 
 * Enable SSL/TLS certificate verification.
 * Set to true to verify the server's certificate against the CA and match the hostname.
 * Set to false or remove to disable verification (less secure).
 */
define( 'MYSQL_SSL_VERIFY_SERVER_CERT', true );

/** Define specific SSL Ciphers to be used. */
define( 'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256' );