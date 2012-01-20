<?php
	// Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
	// Licensed under a 3 clause BSD license (Please see LICENSE.txt)
	// Source code located at https://github.com/stephenfewer/grinder
	
	if( $_SERVER['REQUEST_METHOD'] != 'POST' )
		exit;
		
	define( 'BASE', true );
	
	require_once 'config.php';
	
	require_once 'user.php';
	
	if( !user_isloggedin() )
		exit;
		
	// http://stackoverflow.com/questions/2915864/php-how-to-find-the-time-elapsed-since-a-date-time
	function elapsed( $time )
	{
		$tokens = array (
			31536000 => 'year',
			2592000 => 'month',
			604800 => 'week',
			86400 => 'day',
			3600 => 'hour',
			60 => 'minute',
			1 => 'second'
		);
		
		foreach( $tokens as $unit => $text )
		{
			if( $time < $unit )
				continue;
								
			$count = floor( $time / $unit );
							
			return $count . ' ' . $text . ( ( $count > 1 ) ? 's' : '' );
		}
		
		return '';
	}
	
	function show_users()
	{
		echo "<h3>Login History</h3><ul>";
		$sql = "SELECT logins.ip, logins.date, users.name FROM logins INNER JOIN users ON logins.id=users.id ORDER BY logins.date DESC LIMIT 25;";
		$result = mysql_query( $sql );
		if( $result )
		{
			while( $row = mysql_fetch_array( $result ) )
			{
				echo "<li><span class='message-text'>User '" . htmlentities( $row['name'], ENT_QUOTES ) . "' logged in at " . htmlentities( $row['date'], ENT_QUOTES ) . " via " . htmlentities( $row['ip'], ENT_QUOTES ) . "</span></li><br/>";
			}
			mysql_free_result( $result );
		}
		echo "</ul>";
		
		echo "<h3>Create Account:</h3>";
		echo "<p>New Username: <input id='user_name' value=''></input></p>";
		echo "<p>New Password: <input id='user_password1' type='password' value=''></input></p>";
		echo "<p>Retype the Password: <input id='user_password2' type='password' value=''></input></p>";
		echo "<p>Users E-Mail Address: <input id='user_email' value=''></input></p>";
		echo "<p>Account Type: <select id='account_type'><option selected='selected' user_type='1'>User</option><option user_type='0'>Administrator</option></select></p>";
		echo "<div id='create_button'>Create</div>";
		
		$sql = "SELECT id, name FROM users;";
		$result = mysql_query( $sql );
		if( $result )
		{			
			echo "<h3>Delete Account:</h3><select id='delete_user'>";
			while( $row = mysql_fetch_array( $result ) )
			{
				if( $row['id'] == $_SESSION['id'] )
					continue;
				echo "<option user_id='" . htmlentities( $row['id'], ENT_QUOTES ) . "'>" . htmlentities( $row['name'], ENT_QUOTES ) . "</option>";
			}
			echo "</select><br/><br/><div id='delete_button'>Delete</div>";
			
			mysql_free_result( $result );
		}
	}
	
	function show_overview()
	{
					$unique = 0;
					$sql = "SELECT hash_quick FROM crashes GROUP BY hash_quick;";
					$result = mysql_query( $sql );
					if( $result )
					{	
						$unique = mysql_num_rows( $result );
					
						mysql_free_result( $result );
					}

					if( $unique > 0 )
					{
						$sql = "SELECT SUM(count) AS total FROM crashes;";
						$result = mysql_query( $sql );
						if( $result )
						{
							$row = mysql_fetch_array( $result );
							if( $row )
								echo "<p class='message-text'>A total of " . htmlentities( $row['total'], ENT_QUOTES ) . " crashes have been generated, of which " . htmlentities( $unique, ENT_QUOTES ) . " appear unique.</p>";
								
							mysql_free_result( $result );
						}
					}
					
					$sql = "SELECT * FROM nodes ORDER BY name ASC;";
					$result = mysql_query( $sql );
					if( $result )
					{
						echo "<ul>";
						
						if( mysql_num_rows( $result ) == 0 )
							echo "<li><span class='message-text'>No Grinder nodes are available yet. Go set some up and fuzz something!!!</span></li>";
						
						while( $row = mysql_fetch_array( $result ) )
						{				
							// this server may or may not be be +/- N hours from the Nodes
							$diff = intval( GRINDER_TIMEDIFF );
							
							if( $diff >= 0 )
								$server_time = strtotime( '+' . $diff . ' hours' );
							else
								$server_time = strtotime( $diff . ' hours' );
						
							$running = false;
							$lastcrash_period = null;
							
							$testcases_per_minute = intval( $row['testcases_per_minute'] );
							
							$lastcrash = strtotime( $row['lastcrash'] );
							$lastfuzz  = strtotime( $row['lastfuzz'] );
									
							if( $lastfuzz )
							{
								$window = 5;
								
								if( round( ( $server_time - $lastfuzz ) / 60 ) < $window + 1 )
								{
									$running = true;
								}
							}
							
							if( $lastcrash )
							{
								$lastcrash_period = elapsed( ( $server_time - $lastcrash ) );
							}
							
							if( $running )
							{
								if( $testcases_per_minute > 0 )
									$running = "<span class='message-active'>active</span> and averaging " . htmlentities( $testcases_per_minute, ENT_QUOTES ) . " testcases per minute";
								else
									$running = "<span class='message-active'>active</span>";
							}
							else
							{
								$running = "<span class='message-inactive'>inactive</span>";
							}
							
							echo "<li><span class='message-text'>Node " . htmlentities( $row['name'], ENT_QUOTES ) . " is currently " . $running . ". " . htmlentities( $row['name'], ENT_QUOTES ) ." has generated " . htmlentities( $row['crashes'], ENT_QUOTES ) . " crashes.";
							
							if( intval( $row['crashes'] ) > 0 )
							{
								if( $lastcrash_period )
									echo " The last crash was " . htmlentities( $lastcrash_period, ENT_QUOTES ) . " ago.";
							}
							
							echo "</span></li><br/>";
							
						}
						
						echo "</ul>";
						
						mysql_free_result( $result );
					}
	}
	
	
	if( isset( $_POST['action'] ) )
	{
		$success = false;
		
		$action = mysql_real_escape_string( $_POST['action'] );

		switch( $action )
		{
			case 'add_user':
				if( isset($_POST['name']) and isset($_POST['email']) and isset($_POST['password']) and isset($_POST['type']) )
				{
					$name     = mysql_real_escape_string( trim( $_POST['name'] ) );
					$email    = mysql_real_escape_string( trim( $_POST['email'] ) );
					$password = mysql_real_escape_string( trim( $_POST['password'] ) );
					$type     = intval( mysql_real_escape_string( trim( $_POST['type'] ) ) );
						
					if( empty( $name ) or empty( $email ) or empty( $password ) )
						break;
							
					$success = user_create( $name, $email, $password, $type );
				}
				break;
			case 'delete_user':
				if( isset($_POST['id']) )
				{
					$id = intval( mysql_real_escape_string( trim( $_POST['id'] ) ) );

					$success = user_delete( $id );
				}
				break;
			default:
				break;
		}
		
		if( $success )
			echo 'success';
		else
			echo 'failed';
			
		exit;
	}
	
?>

<!DOCTYPE html>
<html>

	<body>
		
		<script>
		
			function getUserName() { return document.getElementById( 'user_name' ).value; }
			function getUserEmail() { return document.getElementById( 'user_email' ).value.toLowerCase(); }
			function getUserPassword1() { return document.getElementById( 'user_password1' ).value; }
			function getUserPassword2() { return document.getElementById( 'user_password2' ).value; }
			function getUserType() 
			{
				var account_type = document.getElementById( 'account_type' );
				
				var type = account_type.options[ account_type.selectedIndex ];
				
				return type.getAttribute( 'user_type' );
			}
			
			function getDeleteUserId() 
			{
				var delete_user = document.getElementById( 'delete_user' );
				
				var user = delete_user.options[ delete_user.selectedIndex ];
				
				return user.getAttribute( 'user_id' );
			}
			
			var index = 0;
			if( $.cookie( 'grinder-system' ) )
			{
				index = parseInt( $.cookie( 'grinder-system' ) );
				if( index == -1 )
					index = false;
			}
			
			$( '#accordion' ).accordion({
				active: index,
				autoHeight: false,
				animated: false,
				collapsible: true,
				changestart: function(event, ui) { 
					index = $( this ).accordion( 'option', 'active' );
					if( typeof index == 'boolean' && index == false && $.cookie( 'grinder-system' ) )
						index = -1;
					$.cookie( 'grinder-system', index, { expires: 31 } );
					if( index == 0 )
						enableAutoRefresh();
					else
						disableAutoRefresh();
				}
			});
			
			//$( '#accordion' ).accordion( 'option', 'active', $.cookie( 'grinder-system' ) ? parseInt( $.cookie( 'grinder-system' ) ) : 0 );
			
			$( "#create_button" ).button().click( function() {
			
					var user_name      = getUserName();
					var user_email     = getUserEmail();
					var user_password1 = getUserPassword1();
					var user_password2 = getUserPassword2()
					var user_type      = getUserType();

					if( user_type != 0 && user_type != 1 )
						return error_alert( 'Please enter a valid account type.', 'Error!' );
						
					if( user_name.length == 0 )
						return error_alert( 'Please enter a user name.', 'Error!' );
					
					if( user_email.length == 0 )
						return error_alert( 'Please enter a user email address.', 'Error!' );
						
					if( user_password1.length == 0 || user_password2.length == 0 )
						return error_alert( 'Please enter a user password.', 'Error!' );
						
					if( user_password1 != user_password2 )
						return error_alert( 'The user passwords do not match.', 'Error!' );
						
					if( user_name.length < 2 || user_name.length > 16  )
						return error_alert( 'Please enter a username between 2 and 16 charachters.', 'Error!' );
						
					if( user_password1.length < 8 || user_password1.length > 32 )
						return error_alert( 'Please enter a user password between 8 and 32 charachters.', 'Error!' );
					
					var rx = new RegExp( '^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,3})$' );
						
					if( !rx.exec( user_email ) )
						return error_alert( 'Please enter a valid email address.', 'Error!' );
							
					rx = new RegExp( '^[A-Za-z0-9_\-]+$' );
					
					if( !rx.exec( user_name ) )
						return error_alert( 'Please use only ASCII and numeric charachters for the username.', 'Error!' );
					
					if( !rx.exec( user_password1 ) )
						return error_alert( 'Please use only ASCII and numeric charachters for the user password.', 'Error!' );
						
					$.post( 'system.php', { action:'add_user', name:getUserName, email:getUserEmail, password:getUserPassword1, type:getUserType }, function( data ) {
						if( data != 'success' )
							return error_alert( 'Failed to create the account.', 'Error!' );
						error_alert( 'The new user account has been created', 'Success!' );
						refreshTab( 0 );
					});
			} );
			
			$( "#delete_button" ).button().click( function() {
				if( confirm( 'Are you sure you want to delete this user?' ) )
				{
					$.post( 'system.php', { action:'delete_user', id:getDeleteUserId }, function( data ) {
						if( data != 'success' )
							return error_alert( 'Failed to delete the account.', 'Error!' );
						error_alert( 'The user account has been deleated', 'Success!' );
						refreshTab( 0 );
					});
				}
			} );
		</script>
		
		<div id='accordion'>
		
			<h3><a href="#">Overview</a></h3>
			<div>
				<?php
					show_overview();
				?>
			</div>
			
			<?php
				
				if( user_isadministrator() )
				{
					echo "<h3><a href='#'>Users</a></h3><div>";
						
					show_users();
						
					echo "</div>";
				}
			?>

		</div>
		
	</body>

</html>

