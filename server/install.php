<?php
	// Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
	// Licensed under a 3 clause BSD license (Please see LICENSE.txt)
	// Source code located at https://github.com/stephenfewer/grinder
	
	error_reporting( 0 );
	
	function install_gringer( $grinder_key, $grinder_timediff, $db_host, $db_name, $db_user, $db_password, $admin_name, $admin_password, $admin_email, $grinder_domain, $grinder_path )
	{
		if( file_exists( 'config.php' ) )
		{
			echo "<p>Failing, already installed.</p>";
			return false;
		}
		
		echo "<p>Connecting to MySQL... ";
		$conn = mysql_connect( $db_host, $db_user, $db_password );
		if( $conn == false )
		{
			echo "Failed (" . htmlentities( mysql_error() ) . ").</p>";
			return false;
		}
		
		echo "Success.</p><p>Selecting the database... ";
		$db = mysql_select_db( $db_name );
		if( $db == false )
		{
			echo "Failed (" . htmlentities( mysql_error() ) . ").</p>";
			return false;
		}
		
		// create the tables...
		echo "Success.</p><p>Creating the tables... ";
		
		$table_crashes_sql = "CREATE TABLE IF NOT EXISTS crashes (
			id int(11) NOT NULL AUTO_INCREMENT,
			time varchar(32) NOT NULL,
			node varchar(32) NOT NULL,
			target varchar(32) NOT NULL,
			hash varchar(32) NOT NULL,
			hash_quick varchar(8) NOT NULL,
			hash_full varchar(8) NOT NULL,
			type varchar(128) NOT NULL,
			fuzzer varchar(128) NOT NULL,
			verified int(11) NOT NULL DEFAULT 0,
			count int(11) NOT NULL DEFAULT 1,
			owner_id int(11) NOT NULL DEFAULT 0,
			notes text NOT NULL,
			log_data mediumblob NOT NULL,
			crash_data mediumblob NOT NULL,
			PRIMARY KEY (id),
			UNIQUE KEY id (id),
			KEY hash_quick (hash_quick)
		);";
			
		$result = mysql_query( $table_crashes_sql );
		if( $result == false )
		{
			echo "Failed (" . htmlentities( mysql_error() ) . ").</p>";
			return false;
		}
				
		$table_nodes_sql = "CREATE TABLE IF NOT EXISTS nodes (
			name varchar(32) NOT NULL,
			crashes int(11) NOT NULL DEFAULT 0,
			lastcrash varchar(32) NOT NULL,
			lastfuzz varchar(32) NOT NULL,
			testcases_per_minute int(11) NOT NULL DEFAULT 0,
			PRIMARY KEY (name)
		);";
		
		$result = mysql_query( $table_nodes_sql );
		if( $result == false )
		{
			echo "Failed (" . htmlentities( mysql_error() ) . ").</p>";
			return false;
		}
		
		$table_users_sql = "CREATE TABLE IF NOT EXISTS users (
			id int(11) NOT NULL AUTO_INCREMENT,
			name varchar(32) NOT NULL,
			password varchar(40) NOT NULL,
			email varchar(255) NOT NULL,
			type int(11) NOT NULL DEFAULT 0,
			PRIMARY KEY (id)
		);";
		
		$result = mysql_query( $table_users_sql );
		if( $result == false )
		{
			echo "Failed (" . htmlentities( mysql_error() ) . ").</p>";
			return false;
		}
		
		$table_logins_sql = "CREATE TABLE IF NOT EXISTS logins (
			id int(11) NOT NULL,
			ip varchar(255) NOT NULL,
			date timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (id) REFERENCES users (id)
		);";
		
		$result = mysql_query( $table_logins_sql );
		if( $result == false )
		{
			echo "Failed (" . htmlentities( mysql_error() ) . ").</p>";
			return false;
		}
		
		$table_filters_sql = "CREATE TABLE IF NOT EXISTS filters (
			filter_id int(11) NOT NULL AUTO_INCREMENT,
			id int(11) NOT NULL,
			field int(11) NOT NULL,
			value varchar(32) NOT NULL,
			disabled int(11) NOT NULL DEFAULT 0,
			FOREIGN KEY (id) REFERENCES users (id),
			PRIMARY KEY (filter_id)
		);";
		
		$result = mysql_query( $table_filters_sql );
		if( $result == false )
		{
			echo "Failed (" . htmlentities( mysql_error() ) . ").</p>";
			return false;
		}
		
		$table_alerts_sql = "CREATE TABLE IF NOT EXISTS alerts (
			alert_id int(11) NOT NULL AUTO_INCREMENT,
			id int(11) NOT NULL,
			field int(11) NOT NULL,
			value varchar(32) NOT NULL,
			disabled int(11) NOT NULL DEFAULT 0,
			FOREIGN KEY (id) REFERENCES users (id),
			PRIMARY KEY (alert_id)
		);";
		
		$result = mysql_query( $table_alerts_sql );
		if( $result == false )
		{
			echo "Failed (" . htmlentities( mysql_error() ) . ").</p>";
			return false;
		}
		// add the user account...
		echo "Success.</p><p>Adding your account... ";
		
		$grinder_salt = sha1( rand() * time() );
		
		$sql  = "INSERT INTO users ( name, email, password, type ) VALUES ( '" . mysql_real_escape_string( $admin_name ) . "', '" . mysql_real_escape_string( $admin_email ) . "', '" . mysql_real_escape_string( sha1( $grinder_salt . $admin_password ) ) . "', '0' );";

		$result = mysql_query( $sql );
		if( $result == false )
		{
			echo "Failed (" . htmlentities( mysql_error() ) . ").</p>";
			return false;
		}
		
		mysql_free_result( $result );
		
		mysql_close( $conn );
		
		// create the config.php file..
		echo "Success.</p><p>Creating the config.php file... ";
		$config = fopen( 'config.php', 'w' );
		if( $config == false )
		{
			echo "Failed.</p>";
			return false;
		}
		
		$config_data = "<?php
			if( !defined('BASE') )
				exit;

			error_reporting( 0 );
			
			if( !defined( 'NO_SESSION' ) )
			{
				session_name( 'grinder' );
				session_set_cookie_params( 60 * 60 * 24 * 7, '" . $grinder_path . "', '" . $grinder_domain . "' );
				session_start();
			}
			
			define( 'GRINDER_TIMEDIFF', '" . $grinder_timediff . "' );
			
			define( 'GRINDER_KEY', '" . $grinder_key . "' );
			
			define( 'GRINDER_SALT', '" . $grinder_salt . "' );
			
			define( 'HOST', '" . $db_host . "' );
			define( 'DBUSER', '" . $db_user . "' );
			define( 'PASS', '" . $db_password . "' );
			define( 'DB', '" . $db_name . "' );
			
			\$conn = mysql_connect( HOST, DBUSER, PASS ) or die( '<h3>Fatal Error!</h3>' );
			
			\$db = mysql_select_db( DB ) or die( '<h3>Fatal Error!</h3>' );
		?>";

		fwrite( $config, $config_data );
		
		fclose( $config );
		
		// delete this install.php file?
		
		echo "Success.</p><p>Deleting the install.php file... ";
		if( unlink( 'install.php' ) == false )
		{
			echo "Failed.</p>";
			return false;
		}
		echo "Success.</p>";
		
		echo "<p>The Grinder web server has been installed successfully.</p>";
		
		echo "<p><a href='index.php'>You can now login to Grinder...</></p>";
		
		return true;
	}
	
	if( isset( $_POST['action'] ) )
	{
		$success = false;
		
		$action = $_POST['action'];

		switch( $action )
		{
			case 'install':
				if( isset($_POST['grinder_key']) && isset($_POST['grinder_timediff']) && isset($_POST['db_host']) && isset($_POST['db_name']) && isset($_POST['db_user']) && isset($_POST['db_password']) && isset($_POST['admin_name']) && isset($_POST['admin_password']) && isset($_POST['admin_email']) && isset($_POST['grinder_domain']) && isset($_POST['grinder_path']) )
				{
					$grinder_key      = trim( $_POST['grinder_key'] );
					$grinder_timediff = intval( trim( $_POST['grinder_timediff'] ) );
					$db_host          = trim( $_POST['db_host'] );
					$db_name          = trim( $_POST['db_name'] );
					$db_user          = trim( $_POST['db_user'] );
					$db_password      = trim( $_POST['db_password'] );
					$admin_name       = trim( $_POST['admin_name'] );
					$admin_password   = trim( $_POST['admin_password'] );
					$admin_email      = trim( $_POST['admin_email'] );
					$grinder_domain   = trim( $_POST['grinder_domain'] );
					$grinder_path     = trim( $_POST['grinder_path'] );
						
					if( empty( $grinder_key ) or empty( $db_host ) or empty( $db_name ) or empty( $db_user ) or empty( $db_password ) or empty( $admin_name ) or empty( $admin_password ) or empty( $admin_email ) )
						break;
							
					$success = install_gringer( $grinder_key, $grinder_timediff, $db_host, $db_name, $db_user, $db_password, $admin_name, $admin_password, $admin_email, $grinder_domain, $grinder_path );
				}
				break;
			default:
				break;
		}
		
		if( !$success )
			echo "<p>Failed.</p>";
		
		exit;
	}
?>

<!DOCTYPE html>
<html>
	<head>
		<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
		<title>Grinder - Install</title>
		<meta name="robots" content="noindex"/>
		<meta name="copyright" content="Copyright (c) 2011, Harmony Security." />
		<link rel="shortcut icon" type="image/x-icon" href="favicon.ico"/>
		<link type="text/css" href="scripts/jquery/css/ui-lightness/jquery-ui-1.8.16.custom.css" rel="stylesheet" />	
		<link type="text/css" href="style.css" rel="stylesheet" />	
		<script type="text/javascript" src="scripts/jquery/js/jquery-1.6.2.min.js"></script>
		<script type="text/javascript" src="scripts/jquery/js/jquery-ui-1.8.16.custom.min.js"></script>
		<script type="text/javascript" src="scripts/jquery/js/jquery.cookie.js"></script>
		<script type="text/javascript">
		
			function error_alert( message )
			{
				document.getElementById( 'error-message' ).innerHTML = '<p>' + message + '</p>';
				$( "#error-message" ).dialog( "option", "title", 'Error!' );
				$( "#error-message" ).dialog( "open" );
				return false;
			}
			
			function getGrinderKey() { return document.getElementById( 'grinder_key' ).value; }
			function getGrinderTimediff() { return parseInt( document.getElementById( 'grinder_timediff' ).value ); }
			function getDatabaseHost() { return document.getElementById( 'db_host' ).value; }
			function getDatabaseName() { return document.getElementById( 'db_name' ).value; }
			function getDatabaseUser() { return document.getElementById( 'db_user' ).value; }
			function getDatabasePassword() { return document.getElementById( 'db_password' ).value; }
			function getAdministratorName() { return document.getElementById( 'admin_name' ).value; }
			function getAdministratorEmail() { return document.getElementById( 'admin_email' ).value.toLowerCase(); }
			function getAdministratorPassword1() { return document.getElementById( 'admin_password1' ).value; }
			function getAdministratorPassword2() { return document.getElementById( 'admin_password2' ).value; }
			function getGrinderDomain() { return document.getElementById( 'grinder_domain1' ).value; }
			function getGrinderPath() { return document.getElementById( 'grinder_path1' ).value; }
			
			$( function() {
				$( "#tabs" ).tabs();
				
				$( "#error-message" ).dialog({
					modal: true,
					resizable: false,
					autoOpen: false,
					buttons: {
						Ok: function() {
							$( this ).dialog( "close" );
						}
					}
				});
				
				if( window.location.protocol != 'https:' )
					document.getElementById( 'https_warning' ).style.display = 'block';

				document.getElementById( 'grinder_domain1' ).value = location.hostname;
				document.getElementById( 'grinder_path1' ).value = location.pathname.substr( 0, location.pathname.lastIndexOf( '/' ) ) + '/';
					
				$( "#install_button" ).button().click( function() {
				
					var grinder_key      = getGrinderKey();
					var grinder_timediff = getGrinderTimediff();
					var db_host          = getDatabaseHost();
					var db_name          = getDatabaseName();
					var db_user          = getDatabaseUser();
					var db_password      = getDatabasePassword();
					var admin_name       = getAdministratorName();
					var admin_email      = getAdministratorEmail();
					var admin_password1  = getAdministratorPassword1();
					var admin_password2  = getAdministratorPassword2()
					
					if( grinder_key.length == 0 )
						return error_alert( 'Please enter a Grinder Key.' );
					
					if( document.getElementById( 'grinder_timediff' ).value.length == 0 )
						return error_alert( 'Please enter a Grinder server/nodes time difference value.' );

					if( db_host.length == 0 )
						return error_alert( 'Please enter a DB host.' );
						
					if( db_name.length == 0 )
						return error_alert( 'Please enter a DB name.' );
						
					if( db_user.length == 0 )
						return error_alert( 'Please enter a DB user.' );
					
					if( db_password.length == 0 )
						return error_alert( 'Please enter a DB password.' );
					
					if( admin_name.length == 0 )
						return error_alert( 'Please enter a Grinder username.' );
						
					if( admin_email.length == 0 )
						return error_alert( 'Please enter the Grinder usernames email address.' );
						
					if( admin_password1.length == 0 || admin_password2.length == 0 )
						return error_alert( 'Please enter a Grinder user password.' );
						
					if( admin_password1 != admin_password2 )
						return error_alert( 'The Grinder user passwords do not match.' );
						
					if( admin_name.length < 2 || admin_name.length > 16  )
						return error_alert( 'Please enter a Grinder username between 2 and 16 charachters.' );
						
					if( admin_password1.length < 8 || admin_password1.length > 32 )
						return error_alert( 'Please enter a Grinder user password between 8 and 32 charachters.' );
					
					var rx = new RegExp( '^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,3})$' );
						
					if( !rx.exec( admin_email ) )
						return error_alert( 'Please enter a valid email address.' );
					
					rx = new RegExp( '^[A-Za-z0-9_\-]+$' );
					
					if( !rx.exec( admin_name ) )
						return error_alert( 'Please use only ASCII and numeric charachters for your Grinder username.' );
					
					if( !rx.exec( admin_password1 ) )
						return error_alert( 'Please use only ASCII and numeric charachters for your Grinder user password.' );
						
					$.post( 'install.php', { action:'install', grinder_key:getGrinderKey, grinder_timediff:getGrinderTimediff, db_host:getDatabaseHost, db_name:getDatabaseName, db_user:getDatabaseUser, db_password:getDatabasePassword, admin_name:getAdministratorName, admin_email:getAdministratorEmail, admin_password:getAdministratorPassword1, grinder_domain:getGrinderDomain, grinder_path:getGrinderPath }, function( data ) {
						document.getElementById( 'install_status' ).innerHTML = data;
					});
				});
				
			});
		</script>
		<style>
			input {
				width:150px;
			}
			#grinder_key {
				width:300px;
			}
		</style>
	</head>
	<body>

		<center>
			<div id='logo'>
				<img src='images/logo.png' alt='Grinder' title='...and the machine grinds on!'/>
			</div>
		</center>

		<div id="tabs">
			<ul>
				<li><a href="#ui-tabs-1">Install</a></li>
			</ul>
			<div id="ui-tabs-1">
			
				<div style='display:none;' class="ui-widget" id='https_warning'>
					<div class="ui-state-error ui-corner-all" style="padding: 0 .7em;"> 
						<p><span class="ui-icon ui-icon-alert" style="float: left; margin-right: .3em;"></span> 
						<strong>Warning: </strong>You are not viewing this page over HTTPS. You should be viewing this page over HTTPS.</p>
					</div>
				</div>
			
			<?php
				if( file_exists( 'config.php' ) )
				{
					echo "<h3>Welcome</h3>
							<div style='margin-left:30px;'>
								<p>Grinder appears to already be installed!</p>
							</div>";
				}
				else
				{
					echo "<h3>Welcome</h3>
							<div style='margin-left:30px;'>
								<p>Welcome to the Grinder installer. Please create a MySQL database and associated user before continuing. The database user must have SELECT, UPDATE, CREATE, DELETE, ALTER and INSERT privileges. The Grinder Key below must match that of your Grinder Nodes.</p>
							</div>
							
							<h3>Settings</h3>
							<div style='margin-left:30px; margin-right:30px; border-bottom:solid #eeeeee 1px;'>
								<p>Grinder Key (for node updates): <input id='grinder_key' value='AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPP'></input></p>
								<p>Grinder Domain (for session cookies): <input id='grinder_domain1' value=''></input></p>
								<p>Grinder Path (for session cookies): <input id='grinder_path1' value=''></input></p>
								<p>This servers time difference in hours from the Nodes (If any): <input id='grinder_timediff' value='0'></input></p>
							</div>
							<div style='margin-left:30px; margin-right:30px; border-bottom:solid #eeeeee 1px;'>
								<p>Database Host: <input id='db_host' value='localhost'></input></p>
								<p>Database Name: <input id='db_name' value='grinder_db'></input></p>
								<p>Database User: <input id='db_user' value='grinder_db_user'></input></p>
								<p>Database Password: <input id='db_password' type='password' value=''></input></p>
							</div>
							<div style='margin-left:30px; margin-right:30px; border-bottom:solid #eeeeee 1px;'>
								<p>Your Grinder Username: <input id='admin_name' value=''></input></p>
								<p>Your Grinder Password: <input id='admin_password1' type='password' value=''></input></p>
								<p>Retype your Password: <input id='admin_password2' type='password' value=''></input></p>
								<p>Your E-Mail Address: <input id='admin_email' value=''></input></p>
							</div>
							
							<h3>Install</h3>
							<div id='install_status' style='margin-left:30px;'>
								<p>Please review the settings above before clicking Install to finish the process.</p>
								<button id='install_button'>Install...</button>
							</div>";
				}
			?>

			</div>
		</div>
		
		<div id="error-message"></div>
		
	</body>

</html>