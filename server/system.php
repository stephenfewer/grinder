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
					
		$sql = "SELECT name, crashes, testcases_per_minute, lastcrash, lastfuzz FROM nodes ORDER BY name ASC;";
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

?>

<!DOCTYPE html>
<html>

	<body>
		
		<script>
		
			var index = 0;
			if( $.cookie( 'grinder-system' ) )
			{
				index = parseInt( $.cookie( 'grinder-system' ) );
				if( index == -1 )
					index = false;
			}
			
			$( '#system-accordion' ).accordion({
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
				},
				change: function( event, ui ) {
					$( ui.newContent ).find('*[jqplot]').each( function(index) {
						this.plot.replot();
					} );
				}
			});
			
		</script>
		
		<div id='system-accordion'>
		
			<h3><a href="#">Overview</a></h3>
			<div>
				<?php
					show_overview();
				?>
			</div>
			
		</div>
		
	</body>

</html>

