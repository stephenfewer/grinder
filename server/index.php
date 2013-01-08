<?php
	// Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
	// Licensed under a 3 clause BSD license (Please see LICENSE.txt)
	// Source code located at https://github.com/stephenfewer/grinder
	
	define( 'BASE', true ); 
	
	if( !file_exists( 'config.php' ) )
	{
		echo "<a href='install.php'>You must install Grinder.</>";
		exit;
	}
	
	require_once 'config.php';
	
	require_once 'user.php';
	
	if( $_SERVER['REQUEST_METHOD'] == 'POST' )
	{
		$success = false;
		
		if( isset( $_POST['action'] ) )
		{	
			$action = $_POST['action'];

			switch( $action )
			{
				case 'login':
					
					if( user_isloggedin() )
						break;
						
					if( isset($_POST['username']) && isset($_POST['password']) )
					{
						$username = mysql_real_escape_string( trim( $_POST['username'] ) );
						$password = mysql_real_escape_string( trim( $_POST['password'] ) );
							
						if( empty( $username ) or empty( $password ) )
							break;
								
						$success = user_login( $username, $password );
					}
					break;
				case 'logout':
				
					if( !user_isloggedin() )
						break;
						
					$success = user_logout();
					break;
				default:
					break;
			}
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
	<head>
		<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
		<meta http-equiv="pragma" content="no-cache">
		<meta http-equiv="expires" content="-1">
		<title>Grinder</title>
		<meta name="robots" content="noindex"/>
		<link rel="shortcut icon" type="image/x-icon" href="favicon.ico"/>
		<link type="text/css" href="scripts/jquery/css/ui-lightness/jquery-ui-1.8.16.custom.css" rel="stylesheet" />	
		<link type="text/css" href="style.css" rel="stylesheet" />	
		<script type="text/javascript" src="scripts/jquery/js/jquery-1.6.2.min.js"></script>
		<script type="text/javascript" src="scripts/jquery/js/jquery-ui-1.8.16.custom.min.js"></script>
		<script type="text/javascript" src="scripts/jquery/js/jquery.cookie.js"></script>
		
		<script type="text/javascript" src="scripts/jqplot/jquery.jqplot.min.js"></script>
		<!--[if lt IE 9]><script language="javascript" type="text/javascript" src="scripts/jqplot/excanvas.min.js"></script><![endif]-->
		<link rel="stylesheet" type="text/css" href="scripts/jqplot/jquery.jqplot.min.css" />
		<script type="text/javascript" src="scripts/jqplot/plugins/jqplot.barRenderer.min.js"></script>
		<script type="text/javascript" src="scripts/jqplot/plugins/jqplot.categoryAxisRenderer.min.js"></script>
		<script type="text/javascript" src="scripts/jqplot/plugins/jqplot.pointLabels.min.js"></script>

		<script type="text/javascript">
			var owner          =  0;
			var unique         =  1;
			var order          =  1;
			var sort           =  6;
			var offset         =  0;
			var crash_id       =  0;
			var crash_notes    = '';
			var crash_verified = 0;
			var refresh_timer  = null;
			
			function getUsername() { return document.getElementById( 'username' ).value; }
			function getPassword() { return document.getElementById( 'password' ).value; }
			function getUnique() { return unique; }
			function getOwner() { return owner; }
			function getOrder() { return order; }
			function getSort() { return sort; }
			function getOffset() { return offset; }
			function refreshTab( index ) { $( "#tabs" ).tabs( 'load', index ); }
			
			function enableAutoRefresh()
			{
				if( refresh_timer )
					return;
				refresh_timer = setInterval( function() {
					$( "#tabs" ).tabs( 'load', $.cookie( 'grinder-tab' ) ? parseInt( $.cookie( 'grinder-tab' ) ) : 0 );
				}, 5 * 60 * 1000 );
			}
			
			function disableAutoRefresh()
			{
				if( !refresh_timer )
					return;
				clearInterval( refresh_timer );
				refresh_timer = null;
			}
			
			function error_alert( message, title )
			{
				document.getElementById( 'error-message' ).innerHTML = '<p>' + message + '</p>';
				$( "#error-message" ).dialog( "option", "title", title );
				$( "#error-message" ).dialog( "open" );
				return false;
			}
			
			function barchart( id, xlabels, series, series_labels )
			{
				var div = $( '#' + id )[0];
				
				div.plot = $.jqplot( id, series, {
					seriesDefaults: {
						renderer: $.jqplot.BarRenderer,
						rendererOptions: { 
							fillToZero: true,
							barWidth: 30
						},
						pointLabels: { 
							show: true
						}
					},
					series: series_labels,
					legend: {
						show: true,
						placement: 'outsideGrid'
					},
					axes: {
						xaxis: {
							renderer: $.jqplot.CategoryAxisRenderer,
							ticks: xlabels
						}
					}
				} );
				
				div.setAttribute( 'jqplot', true );
				
				return true;
			}
			
			$( function() {
				$( "#tabs" ).tabs( {
					ajaxOptions: {
						type: "post",
						data: { unique:getUnique, owner:getOwner, order:getOrder, sort:getSort, offset:getOffset },
						error: function( xhr, status, index, anchor ) {
							$( anchor.hash ).html( "Couldn't load this tab. We'll try to fix this as soon as possible." );
						}
					},
					select: function( event, ui ) {
						$.cookie( 'grinder-tab', ui.index, { expires: 31 } );
					},
					selected: $.cookie( 'grinder-tab' ) ? parseInt( $.cookie( 'grinder-tab' ) ) : 0
				} );

				$( "#login_button" ).button().click( function() {
				
					if( getUsername().length == 0  )
						return error_alert( 'Please enter a username.', 'Error!' );
						
					if( getPassword().length == 0 )
						return error_alert( 'Please enter a password.', 'Error!' );
						
					if( getUsername().length < 2 || getUsername().length > 16  )
						return error_alert( 'Please enter a username between 2 and 16 charachters.', 'Error!' );
						
					if( getPassword().length < 8 || getPassword().length > 32 )
						return error_alert( 'Please enter a password between 8 and 32 charachters.', 'Error!' );
						
					var rx = new RegExp( '^[A-Za-z0-9_\-]+$' );
					
					if( !rx.exec( getUsername() ) )
						return error_alert( 'Please use only ASCII and numeric charachters for your username.', 'Error!' );
					
					if( !rx.exec( getPassword() ) )
						return error_alert( 'Please use only ASCII and numeric charachters for your password.', 'Error!' );
						
					$.post( 'index.php', { action:'login', username:getUsername, password:getPassword }, function( data ) {
						if( data == 'failed' )
							error_alert( 'Login failed.', 'Error!' );
						else
							location.href = location.href;
					});
				} );
				
				$( "#logout_button" ).button( { icons: { primary: "ui-icon-eject" } } ).click( function() {
					$.post( 'index.php', { action:'logout' }, function( data ) {
						location.href = location.href.substr( 0, location.href.indexOf( '#', 0 ) );
					});
				} );
				
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
				
				$( "#about-message" ).dialog({
					modal: true,
					title: 'About',
					position: 'center',
					resizable: false,
					autoOpen: false,
					width: 600,
					height: 210,
					buttons: {
						Ok: function() {
							$( this ).dialog( "close" );
						}
					}
				});
				
				
				$( "#crash-dialog" ).dialog({
					autoOpen: false,
					position: 'center',
					minWidth: 600,
					width: 600,
					minHeight: 400,
					height: 600,
					modal: true,
					buttons: {
						//Delete: function() {
						//	deleteCrash();
						//},
						Update: function() {
							updateCrash();
						},
						Cancel: function() {
							$( this ).dialog( "close" );
						}
					}
					
				});
				
				var https_warning = document.getElementById( 'https_warning' );
				if( https_warning && window.location.protocol != 'https:' )
					https_warning.style.display = 'block';
				
				enableAutoRefresh();
			} );
		</script>
		<style>
			#logout_button {
				float: right;
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
		
			<?php
				if( user_isloggedin() )
				{
					echo "<ul>";
					echo "<li><a href='system.php'>System</a></li>";
					echo "<li><a href='crashes.php'>Crashes</a></li>";
					echo "<li><a href='fuzzers.php'>Fuzzers</a></li>";
					if( user_isadministrator() )
						echo "<li><a href='settings.php'>Settings</a></li>";
					echo "<li><a href='account.php'>My Account</a></li>";
					echo "<button id='logout_button' title='Logout' style='width:30px;height:30px;'>&nbsp;</button>";
					echo "</ul>";
				}
				else
				{
					echo "	<ul>
								<li><a href='#ui-tabs-1'>Login</a></li>
							</ul>
							<div id='ui-tabs-1'>
							
								<div style='display:none;' class='ui-widget' id='https_warning'>
									<div class='ui-state-error ui-corner-all' style='padding: 0 .7em;'> 
										<p><span class='ui-icon ui-icon-alert' style='float: left; margin-right: .3em;'></span> 
										<strong>Warning: </strong>You are not viewing this page over HTTPS. You should be viewing this page over HTTPS.</p>
									</div>
								</div>
							
								<p>Please login to the system.</p>
								<div style='margin-left:30px;'>
									<p>Username: <input id='username' value=''></input></p>
									<p>Password: <input id='password' type='password' value=''></input></p>
									<button id='login_button'>Login...</button>
								</div>
							</div>";
				}

			?>
		</div>

		<div id='crash-dialog' title=''></div>
		
		<div id="error-message"></div>
		
		<div id="about-message">
			<p>Version: 0.5-Dev</p>
			<p>Author: Stephen Fewer of Harmony Security (<a href='http://www.harmonysecurity.com/' target='_blank'>www.harmonysecurity.com</a>)</p>
			<p>Source Code: <a href='https://github.com/stephenfewer/grinder' target='_blank'>github.com/stephenfewer/grinder</a></p>
		</div>
		
		<center>
			<div id='footer'>
				<a onclick='$( "#about-message" ).dialog( "open" );' href='#'>Grinder v0.5-Dev</a>
			</div>
		</center>
		
	</body>

</html>
