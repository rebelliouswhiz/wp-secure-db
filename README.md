### A simple db.php to enable X.509 database connection for WordPress.

WordPress natively supports the SSL connection to the database by defining in wp-config.php below as [discussed here](https://core.trac.wordpress.org/ticket/28625):

```
define( 'MYSQL_CLIENT_FLAGS', MYSQLI_CLIENT_SSL );
```

But it's very little documented and cannot be found on WordPress' official documentation. Also, it lacks the X.509 verification method if you want the connection to your database over the public network to be more secure.

With the help of Gemini 2.5 Pro and Claude Sonnet 4.5 (which essentially copied the idea from [here](https://core.trac.wordpress.org/attachment/ticket/28625/db.php)), I made this db.php with the idea that it might help someone.

# Usage

1. Download the file and place it in your `/wp-content` directory of the WordPress directory.

    `wget https://raw.githubusercontent.com/rebelliouswhiz/wp-secure-db/refs/heads/main/db.php`

2. Set the following options in your `wp-config.php` before the line `/* That's all, stop editing! Happy publishing. */`:

    ```
    define( 'MYSQL_CLIENT_FLAGS', MYSQLI_CLIENT_SSL );
    define( 'MYSQL_SSL_KEY', '/path/to/your/client-key.pem' );
    define( 'MYSQL_SSL_CERT', '/path/to/your/client-cert.pem' );
    define( 'MYSQL_SSL_CA', '/path/to/your/ca-cert.pem' );

    // Required, or it will fall back to the regular SSL connection
    define( 'MYSQL_SSL_VERIFY_SERVER_CERT', true );

    // Optional
    define( 'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256' );
    ```
    
3. Make sure `db.php` has proper ownership and permissions: `chmod 755 db.php`

You might also want to ensure your database user accepts the X509 connection only to maximize your security.

# Known Issues

- It might break some plugin installations, but it should be fine with most.
- It will break the W3 Total Cache database cache. Please disable it before use.