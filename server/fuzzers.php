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

	function show_fuzzers_overview()
	{
		$sql = "SELECT fuzzer, SUM(count), COUNT(DISTINCT hash_quick) FROM crashes GROUP BY fuzzer;";
		$result = mysql_query( $sql );
		if( $result )
		{	
			$total_fuzzers = mysql_num_rows( $result );
			if( $total_fuzzers == 0 )
			{
				echo "<p class='message-text'>No fuzzers have been seen in the system. Go set some up and fuzz something!!!</p>";
			}
			else
			{
				echo "<p class='message-text'>A total of " . htmlentities( $total_fuzzers, ENT_QUOTES ) . " fuzzers have been seen in the system.</p>";
				
				$div_id = 'Overview_' . rand() . '';
				
				$chart_labels = '[';
				$chart_value1 = '[';
				$chart_value2 = '[';
				
				while( $row = mysql_fetch_array( $result ) )
				{
					if( strlen( $chart_labels ) > 1 )
						$chart_labels .= ',';
								
					if( strlen( $chart_value1 ) > 1 )
						$chart_value1 .= ',';
								
					if( strlen( $chart_value2 ) > 1 )
						$chart_value2 .= ',';
								
					$chart_labels .= "'" . htmlentities( $row['fuzzer'], ENT_QUOTES ) . "'";
							
					$chart_value1 .= htmlentities( $row['COUNT(DISTINCT hash_quick)'], ENT_QUOTES );
							
					$chart_value2 .= htmlentities( $row['SUM(count)'], ENT_QUOTES );
				}
				
				$chart_labels .= ']';
				$chart_value1 .= ']';
				$chart_value2 .= ']';
				
				$series_labels = "[ {label:'Unique Crashes'}, {label:'Total Crashes'} ]";
				
				$chart_width = ( ( 60 * 2 ) * mysql_num_rows( $result ) ) + 200;
						
				if( $chart_width > 1024 )
					$chart_width = 1024;
				
				if( $chart_width < 320 )
					$chart_width = 320;
				
				echo "<div id='" . htmlentities( $div_id, ENT_QUOTES ) . "' style='width:" . $chart_width . "px; height:200px;'></div>";

				echo "<script>barchart( '" . htmlentities( $div_id, ENT_QUOTES ) . "', " . $chart_labels . ", [ " . $chart_value1 . ", " . $chart_value2 . "], " . $series_labels . " );</script>";
			}
			
			mysql_free_result( $result );
		}
	}
	
	function show_fuzzer_details()
	{
		$sql = "SELECT fuzzer, SUM(count), COUNT(DISTINCT hash_quick) FROM crashes GROUP BY fuzzer ASC;";
		$result = mysql_query( $sql );
		if( $result )
		{	
			$total_fuzzers = mysql_num_rows( $result );
			if( $total_fuzzers > 0 )
			{				
				while( $row = mysql_fetch_array( $result ) )
				{
					$sql2 = "SELECT target, SUM(count), COUNT(DISTINCT hash_quick) FROM crashes WHERE fuzzer = '" . mysql_real_escape_string( $row['fuzzer'] ) . "' GROUP BY target ASC;";
					$result2 = mysql_query( $sql2 );
					if( $result2 )
					{
						echo "<h3><a href='#'>" . htmlentities( $row['fuzzer'], ENT_QUOTES ) . "</a></h3>";
						
						echo "<div>";
						
						echo "<p>Fuzzer " . htmlentities( $row['fuzzer'], ENT_QUOTES ) . " has generated " . htmlentities( $row['SUM(count)'], ENT_QUOTES ) . " crashes, of which " . htmlentities( $row['COUNT(DISTINCT hash_quick)'], ENT_QUOTES ) . " appear unique for this fuzzer.</p>";
						
						$div_id = '' . $row['fuzzer'] . '_' . rand() . '';
						
						$chart_labels = '[';
						$chart_value1 = '[';
						$chart_value2 = '[';
						
						while( $row2 = mysql_fetch_array( $result2 ) )
						{
							if( strlen( $chart_labels ) > 1 )
								$chart_labels .= ',';
								
							if( strlen( $chart_value1 ) > 1 )
								$chart_value1 .= ',';
								
							if( strlen( $chart_value2 ) > 1 )
								$chart_value2 .= ',';
								
							$chart_labels .= "'" . htmlentities( $row2['target'], ENT_QUOTES ) . "'";
							
							$chart_value1 .= htmlentities( $row2['COUNT(DISTINCT hash_quick)'], ENT_QUOTES );
							
							$chart_value2 .= htmlentities( $row2['SUM(count)'], ENT_QUOTES );
						}
						
						$chart_labels .= ']';
						$chart_value1 .= ']';
						$chart_value2 .= ']';
						
						// SELECT target, COUNT(DISTINCT hash_quick) FROM crashes WHERE fuzzer<>'' GROUP BY target ASC;
						
						$series_labels = "[ {label:'Unique Crashes'}, {label:'Total Crashes'} ]";

						$chart_width = ( ( 60 * 2 ) * mysql_num_rows( $result2 ) ) + 200;
						
						if( $chart_width > 1024 )
							$chart_width = 1024;
							
						if( $chart_width < 320 )
							$chart_width = 320;
							
						echo "<div id='" . htmlentities( $div_id, ENT_QUOTES ) . "' style='width:" . $chart_width . "px; height:200px;'></div>";
						
						echo "<script>barchart( '" . htmlentities( $div_id, ENT_QUOTES ) . "', " . $chart_labels . ", [ " . $chart_value1 . ", " . $chart_value2 . "], " . $series_labels . " );</script>";

						echo "</div>";
						
						mysql_free_result( $result2 );
					}

				}
			}
			
			mysql_free_result( $result );
		}
	}
?>

<!DOCTYPE html>
<html>

	<body>

		<script>
		
			var index = 0;
			if( $.cookie( 'grinder-fuzzers' ) )
			{
				index = parseInt( $.cookie( 'grinder-fuzzers' ) );
				if( index == -1 )
					index = false;
			}
			
			$( '#fuzzers-accordion' ).accordion({
				active: index,
				autoHeight: false,
				animated: false,
				collapsible: true,
				changestart: function(event, ui) { 
					index = $( this ).accordion( 'option', 'active' );
					if( typeof index == 'boolean' && index == false && $.cookie( 'grinder-fuzzers' ) )
						index = -1;
					$.cookie( 'grinder-fuzzers', index, { expires: 31 } );
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
		
		<div id='fuzzers-accordion'>
		
			<h3><a href="#">Overview</a></h3>
			<div>
				<?php show_fuzzers_overview(); ?>
			</div>
			
			<?php show_fuzzer_details(); ?>
			
		</div>
		
	</body>

</html>