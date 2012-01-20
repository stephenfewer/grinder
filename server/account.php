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
		
	if( isset( $_POST['action'] ) )
	{
		$success = false;
		
		$action = mysql_real_escape_string( $_POST['action'] );

		switch( $action )
		{
			case 'change_password':
				if( isset($_POST['new_password']) )
				{
					$new_password = mysql_real_escape_string( trim( $_POST['new_password'] ) );
						
					if( empty( $new_password ) )
						break;
							
					$success = user_change_password( $new_password );
				}
				break;
			case 'change_email':
				if( isset($_POST['new_email']) )
				{
					$new_email = mysql_real_escape_string( trim( $_POST['new_email'] ) );
						
					if( empty( $new_email ) )
						break;
							
					$success = user_change_email( $new_email );
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
			function getEmail() { return document.getElementById( 'user_email1' ).value.toLowerCase(); }
			function getPassword1() { return document.getElementById( 'user_password1' ).value; }
			function getPassword2() { return document.getElementById( 'user_password2' ).value; }
			
			disableAutoRefresh();
			
			var index = 0;
			if( $.cookie( 'grinder-account-settings' ) )
			{
				index = parseInt( $.cookie( 'grinder-account-settings' ) );
				if( index == -1 )
					index = false;
			}
			
			$( '#account_accordion' ).accordion({
				collapsible: true,
				active: index,
				autoHeight: false,
				animated: false,
				changestart: function(event, ui) { 
					index = $( this ).accordion( 'option', 'active' );
					if( typeof index == 'boolean' && index == false && $.cookie( 'grinder-account-settings' ) )
						index = -1;
					$.cookie( 'grinder-account-settings', index, { expires: 31 } );
				}
			});
			

			
			$( "#changeemail_button" ).button().click( function() {
				var user_email = getEmail();

				if( user_email.length == 0 )
					return error_alert( 'Please enter a new email address.', 'Error!' );

				var rx = new RegExp( '^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,3})$' );
					
				if( !rx.exec( user_email ) )
					return error_alert( 'Please enter a valid email address.', 'Error!' );
						
				$.post( 'account.php', { action:'change_email', new_email:getEmail }, function( data ) {
					if( data == 'success' )
						return error_alert( 'Your email address has been changed.', 'Success!' );
					else
						return error_alert( 'Failed to change your email address.', 'Error!' );
				});
			});
			
			$( "#changepassword_button" ).button().click( function() {
				
				var user_password1 = getPassword1();
				var user_password2 = getPassword2()
					
				if( user_password1.length == 0 || user_password2.length == 0 )
					return error_alert( 'Please enter a new user password.', 'Error!' );
						
				if( user_password1 != user_password2 )
					return error_alert( 'The new user passwords do not match.', 'Error!' );
	
				if( user_password1.length < 8 || user_password1.length > 32 )
					return error_alert( 'Please enter a new user password between 8 and 32 charachters.', 'Error!' );
						
				var rx = new RegExp( '^[A-Za-z0-9_\-]+$' );
					
				if( !rx.exec( user_password1 ) )
					return error_alert( 'Please use only ASCII and numeric charachters for your new user password.', 'Error!' );
						
				$.post( 'account.php', { action:'change_password', new_password:getPassword1 }, function( data ) {
					if( data == 'success' )
						return error_alert( 'Your password has been changed.', 'Success!' );
					else
						return error_alert( 'Failed to change your password.', 'Error!' );
				});
			});
		</script>
		
		<div id='account_accordion'>
		
			<h3><a href="#">Recent Logins</a></h3>
			<div>
				<ul>
				<?php
					$sql = "SELECT * FROM logins WHERE id='" . mysql_real_escape_string( $_SESSION['id'] ) . "' ORDER BY date DESC LIMIT 10;";
					$result = mysql_query( $sql );
					if( $result )
					{
						while( $row = mysql_fetch_array( $result ) )
						{
							echo "<li><span class='message-text'>User '" . htmlentities( $_SESSION['username'], ENT_QUOTES ) . "' logged in at " . htmlentities( $row['date'], ENT_QUOTES ) . " via " . htmlentities( $row['ip'], ENT_QUOTES ) . "</span></li><br/>";
						}
						mysql_free_result( $result );
					}
				?>
				</ul>
			</div>
			
			<h3><a href="#">Change Password</a></h3>
			<div>
				<p>Your New Password: <input id='user_password1' type='password' value=''></input></p>
				<p>Retype the Password: <input id='user_password2' type='password' value=''></input></p>
				<button id='changepassword_button'>Change Password...</button>
			</div>
			
			<h3><a href="#">Change E-Mail</a></h3>
			<div>
				<p>Your E-Mail Address: <input id='user_email1' style='width:300px;' value='<?php echo htmlentities( $_SESSION['email'], ENT_QUOTES ); ?>'></input></p>
				<button id='changeemail_button'>Change E-Mail Address...</button>
			</div>
		
		</div>

		<div id="message-dialog"></div>
	</body>

</html>
