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
		
	$fields = array( 'Node', 'Target', 'Fuzzer', 'Type', 'Hash', 'Quick Hash', 'Full Hash', 'Unique', 'Verified' );
	$fields_sql = array( 'node', 'target', 'fuzzer', 'type', 'hash', 'hash_quick', 'hash_full', 'unique', 'verified' );

	function create_filter( $field, $value )
	{
		$success = false;
		
		$sql  = "INSERT INTO filters ( id, field, value, disabled ) VALUES ";
		$sql .= "( '" . mysql_real_escape_string( $_SESSION['id'] ) . "', '" . $field . "', '" .  $value . "', '0' );";
						
		$result = mysql_query( $sql );
		if( $result )
		{
			$success = true;
			mysql_free_result( $result );
		}
		
		return $success;
	}
	
	function delete_filter( $filter_id )
	{
		$success = false;
		
		$sql = "DELETE FROM filters WHERE filter_id='" . $filter_id . "' AND id='" . mysql_real_escape_string( $_SESSION['id'] ) . "' LIMIT 1;";
		
		$result = mysql_query( $sql );
		if( $result )
		{
			$success = true;
			mysql_free_result( $result );
		}
		
		return $success;
	}
	
	function create_alert( $field, $value )
	{
		$success = false;
		
		$sql  = "INSERT INTO alerts ( id, field, value, disabled ) VALUES ";
		$sql .= "( '" . mysql_real_escape_string( $_SESSION['id'] ) . "', '" . $field . "', '" . $value . "', '0' );";
						
		$result = mysql_query( $sql );
		if( $result )
		{
			$success = true;
			mysql_free_result( $result );
		}
		
		return $success;
	}
	
	function delete_alert( $alert_id )
	{
		$success = false;
		
		$sql = "DELETE FROM alerts WHERE alert_id='" . $alert_id . "' AND id='" . mysql_real_escape_string( $_SESSION['id'] ) . "' LIMIT 1;";
		
		$result = mysql_query( $sql );
		if( $result )
		{
			$success = true;
			mysql_free_result( $result );
		}
		
		return $success;
	}
	
	if( isset( $_POST['action'] ) )
	{
		$success = false;
		
		$action = mysql_real_escape_string( $_POST['action'] );

		switch( $action )
		{
			case 'create_filter':
				if( isset($_POST['field']) and isset($_POST['value']) )
				{
					$field = intval( mysql_real_escape_string( trim( $_POST['field'] ) ) );
					$value = mysql_real_escape_string( trim( $_POST['value'] ) );
						
					if( empty( $value ) or $field < 0 or $field >= count( $fields ) )
						break;
							
					$success = create_filter( $field, $value );
				}
				break;
			case 'delete_filter':
				if( isset($_POST['filter_id']) )
				{
					$filter_id = intval( mysql_real_escape_string( trim( $_POST['filter_id'] ) ) );
	
					$success = delete_filter( $filter_id );
				}
				break;
			case 'create_alert':
				if( isset($_POST['field']) and isset($_POST['value']) )
				{
					$field = intval( mysql_real_escape_string( trim( $_POST['field'] ) ) );
					$value = mysql_real_escape_string( trim( $_POST['value'] ) );
						
					if( empty( $value ) or $field < 0 or $field >= count( $fields ) )
						break;
							
					$success = create_alert( $field, $value );
				}
				break;
			case 'delete_alert':
				if( isset($_POST['alert_id']) )
				{
					$alert_id = intval( mysql_real_escape_string( trim( $_POST['alert_id'] ) ) );
	
					$success = delete_alert( $alert_id );
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
			function _unique( checkbox )
			{
				unique = checkbox.checked ? 1 : 0;
				refreshTab( 1 );
			}
			
			function _owner( checkbox )
			{
				owner = checkbox.checked ? 1 : 0;
				refreshTab( 1 );
			}
			
			function _sort( s )
			{
				if( s == sort )
					order = order == 0 ? 1 : 0;
				sort = s;		
				refreshTab( 1 );
			}
			
			function _offset( o )
			{
				offset = o;		
				refreshTab( 1 );
			}
			
			function _crash_click( _id, _hash )
			{
				$( '#crash-dialog' ).load( 'crash.php', { id:_id }, function() {
					$( "#crash-dialog" ).dialog( 'option', 'title', 'Crash: ' + _hash );
					$( '#crash-dialog' ).dialog( 'open' );
				});
			}

			function _delete_filter_click( _filter_id )
			{
				if( confirm( 'Are you sure you want to delete this filter?' ) )
				{
					$.post( 'crashes.php', { action:'delete_filter', filter_id:_filter_id }, function( data ) {
						if( data != 'success' )
							return error_alert( 'Failed to delete the filter.', 'Error!' );
						error_alert( 'The filter has been deleated.', 'Success!' );
						refreshTab( 1 );
					});
				}
			}
			
			function _delete_alert_click( _alert_id )
			{
				if( confirm( 'Are you sure you want to delete this alert?' ) )
				{
					$.post( 'crashes.php', { action:'delete_alert', alert_id:_alert_id }, function( data ) {
						if( data != 'success' )
							return error_alert( 'Failed to delete the alert.', 'Error!' );
						error_alert( 'The alert has been deleated.', 'Success!' );
						refreshTab( 1 );
					});
				}
			}
			
			function getNewFilterValue() { return document.getElementById( 'filter_value_input' ).value; }
			
			function getNewAlertValue() { return document.getElementById( 'alert_value_input' ).value; }
			
			function getNewFilterField() 
			{
				var filter_field_option = document.getElementById( 'filter_field_option' );
				
				var field = filter_field_option.options[ filter_field_option.selectedIndex ];
				
				return field.getAttribute( 'filter_field' );
			}
			
			function getNewAlertField() 
			{
				var alert_field_option = document.getElementById( 'alert_field_option' );
				
				var field = alert_field_option.options[ alert_field_option.selectedIndex ];
				
				return field.getAttribute( 'alert_field' );
			}
			
			var index = 0;
			if( $.cookie( 'grinder-crashes-settings' ) )
			{
				index = parseInt( $.cookie( 'grinder-crashes-settings' ) );
				if( index == -1 )
					index = false;
			}
			
			$( '#crashes_settings_accordion' ).accordion({
				collapsible: true,
				active: index,
				autoHeight: false,
				animated: false,
				changestart: function(event, ui) { 
					index = $( this ).accordion( 'option', 'active' );
					if( typeof index == 'boolean' && index == false && $.cookie( 'grinder-crashes-settings' ) )
						index = -1;
					$.cookie( 'grinder-crashes-settings', index, { expires: 31 } );
				}
			});

			$( ".delete_filter_button" ).button( {
				icons: { primary: "ui-icon-trash" }
			} );
			
			$( ".delete_alert_button" ).button( {
				icons: { primary: "ui-icon-trash" }
			} );
			
			$( "#filter_create_button" ).button().click( function() {
				
				if( getNewFilterValue().length == 0 )
					return error_alert( 'Please enter a new filter value.', 'Error!' );
			
				$.post( 'crashes.php', { action:'create_filter', field:getNewFilterField, value:getNewFilterValue }, function( data ) {
					if( data != 'success' )
						return error_alert( 'Failed to create the filter.', 'Error!' );
					error_alert( 'The new filter has been created.', 'Success!' );
					refreshTab( 1 );
				});
			});
			
			$( "#alert_create_button" ).button().click( function() {
				
				if( getNewAlertValue().length == 0 )
					return error_alert( 'Please enter a new alert value.', 'Error!' );
			
				$.post( 'crashes.php', { action:'create_alert', field:getNewAlertField, value:getNewAlertValue }, function( data ) {
					if( data != 'success' )
						return error_alert( 'Failed to create the alert.', 'Error!' );
					error_alert( 'The new alert has been created.', 'Success!' );
					refreshTab( 1 );
				});
			});
			
			$( "#unique_alert_create_button" ).button().click( function() {
				$.post( 'crashes.php', { action:'create_alert', field:'7', value:'1' }, function( data ) {
					if( data != 'success' )
						return error_alert( 'Failed to create the alert.', 'Error!' );
					error_alert( 'The new alert has been created.', 'Success!' );
					refreshTab( 1 );
				});
			});
			
			$( "#verified_alert_create_button" ).button().click( function() {
				$.post( 'crashes.php', { action:'create_alert', field:'8', value:'1' }, function( data ) {
					if( data != 'success' )
						return error_alert( 'Failed to create the alert.', 'Error!' );
					error_alert( 'The new alert has been created.', 'Success!' );
					refreshTab( 1 );
				});
			});
			
			enableAutoRefresh();
			
		</script>
		

				<?php
					$filter_unique = true;
					if( isset( $_POST['unique'] ) )
					{
						$unique = intval( mysql_real_escape_string( $_POST['unique'] ) );
						if( $unique == 0 )
							$filter_unique = false;
						else if( $unique == 1 )
							$filter_unique = true;
					}
					
					$display_owner = false;
					if( isset( $_POST['owner'] ) )
					{
						$owner = intval( mysql_real_escape_string( $_POST['owner'] ) );
						if( $owner == 1 )
							$display_owner = true;
					}
					
					$order_by = 1;
					if( isset( $_POST['order'] ) )
					{
						$order = intval( mysql_real_escape_string( $_POST['order'] ) );
						if( $order == 0 )
							$order_by = 0;
						else if( $order == 1 )
							$order_by = 1;
					}
					
					$orders = array( 'verified', 'node', 'target', 'fuzzer', 'type', 'hash_quick', 'time', 'count' );
					$order_index = 6;
					if( isset( $_POST['sort'] ) )
					{
						$sort = intval( mysql_real_escape_string( $_POST['sort'] ) );
						if( $sort >= 0 and $sort < count( $orders ) )
							$order_index = $sort;
					}
					
					$offset = 0;
					if( isset( $_POST['offset'] ) )
					{
						$offset = intval( mysql_real_escape_string( $_POST['offset'] ) );
					}
				?>

				<table width='100%' border='0' cellspacing='0' cellpadding='0'>
					<tr>
						<td title='The verified status of this crash.'>
							<a href='javascript:_sort(0);'><?php echo ( ( $order_index == 0 ) ? "V " . ( ( $order_by == 1 ) ? "&uarr; " : "&darr;" ) : "V" ); ?></a>
						</td>
						<td title='The Grinder node which generated this crash.'>
							<a href='javascript:_sort(1);'><?php echo ( ( $order_index == 1 ) ? "NODE " . ( ( $order_by == 1 ) ? "&uarr; " : "&darr;" ) : "NODE" ); ?></a>
						</td>
						<td title='The effected target application.'>
							<a href='javascript:_sort(2);'><?php echo ( ( $order_index == 2 ) ? "TARGET " . ( ( $order_by == 1 ) ? "&uarr; " : "&darr;" ) : "TARGET" ); ?></a>
						</td>
						<td title='The Grinder fuzzer which generated this crash.'>
							<a href='javascript:_sort(3);'><?php echo ( ( $order_index == 3 ) ? "FUZZER " . ( ( $order_by == 1 ) ? "&uarr; " : "&darr;" ) : "FUZZER" ); ?></a>
						</td>
						<td title='The type of crash.'>
							<a href='javascript:_sort(4);'><?php echo ( ( $order_index == 4 ) ? "TYPE " . ( ( $order_by == 1 ) ? "&uarr; " : "&darr;" ) : "TYPE" ); ?></a>
						</td>
						<td title='The unique hash to identify this crash.'>
							<a href='javascript:_sort(5);'><?php echo ( ( $order_index == 5 ) ? "HASH " . ( ( $order_by == 1 ) ? "&uarr; " : "&darr;" ) : "HASH" ); ?></a>
						</td>
						<td title='The date this crash was first seen.'>
							<a href='javascript:_sort(6);'><?php echo ( ( $order_index == 6 ) ? "TIME " . ( ( $order_by == 1 ) ? "&uarr; " : "&darr;" ) : "TIME" ); ?></a>
						</td>
						<td title='The number of times this crash has been generated.'>
							<a href='javascript:_sort(7);'><?php echo ( ( $order_index == 7 ) ? "COUNT " . ( ( $order_by == 1 ) ? "&uarr; " : "&darr;" ) : "COUNT" ); ?></a>
						</td>
					</tr>
					
					<?php
						$total = 0;
						$limit = 25;
						
						$sql = "";
						if( $filter_unique and !$display_owner )
							$sql = "SELECT id, hash_quick, hash_full, verified, node, target, fuzzer, type, time, count, SUM(count) FROM crashes";
						else
							$sql = "SELECT id, hash_quick, hash_full, verified, node, target, fuzzer, type, time, count FROM crashes";
						
						$where_count = 0;
						if( $display_owner )
						{
							$where_count = 1;
							$sql .= " WHERE owner_id='" . mysql_real_escape_string( $_SESSION['id'] ) . "'";
						}
						
						$filters_sql = "SELECT field, value FROM filters WHERE id='" . mysql_real_escape_string( $_SESSION['id'] ) . "' AND disabled='0';";
						$filters_result = mysql_query( $filters_sql );
						if( $filters_result )
						{						
							while( $filters_row = mysql_fetch_array( $filters_result ) )
							{
								$field = $filters_row['field'];
								
								if( $field < 0 or $field >= count( $fields_sql ) )
									continue;

								if( $where_count == 0 )
									$sql .= " WHERE";
									
								if( $where_count > 0 )
									$sql .= " AND";
									
								//array( 'Node', 'Target', 'Fuzzer', 'Type', 'Hash', 'Quick Hash', 'Full Hash' );
								$sql .= " " . mysql_real_escape_string( strtolower( $fields_sql[$field] ) ) . "<>'" . mysql_real_escape_string( $filters_row['value'] ) . "'";
								
								$where_count += 1;
							}
							
							mysql_free_result( $filters_result );
						}			

						if( $filter_unique and !$display_owner )
							$sql .= " GROUP BY hash_quick";
							
						if( $orders[ $order_index ] == 'count' and $filter_unique )
							$sql .= " ORDER BY SUM(count)";
						else
							$sql .= " ORDER BY " . $orders[ $order_index ] . "";

						$result = mysql_query( $sql );
						if( $result )
						{
							$total = mysql_num_rows( $result );
							if( $total == 0 )
							{
								echo "</table><p>No crashes have been recorded.</p>";
							}
							
							mysql_free_result( $result );
							
							if( $order_by == 0 )
								$sql .= " ASC";
							else if( $order_by == 1 )
								$sql .= " DESC";

							$sql .= " LIMIT " . mysql_real_escape_string( $limit ) . " OFFSET " . mysql_real_escape_string( $offset ) . ";";
							
							$result = mysql_query( $sql );
							if( $result )
							{
								while( $row = mysql_fetch_array( $result ) )
								{
								
									echo "<tr class='crash' onclick='javascript:_crash_click(\"" . htmlentities( $row['id'], ENT_QUOTES ) . "\", \"" . htmlentities( $row['hash_quick'], ENT_QUOTES ) . "." . htmlentities( $row['hash_full'], ENT_QUOTES ) . "\");'>";

									echo "<td ";
									switch( $row['verified'] )
									{
										case 0:
											echo "class='crash_unknown'";
											break;
										case 1:
											echo "class='crash_interesting'";
											break;
										case 2:
											echo "class='crash_uninteresting'";
											break;
										case 3:
											echo "class='crash_exploitable'";
											break;
										default:
											echo "class='crash_unknown'";
											break;
									}
									echo ">&nbsp;</td>";
									
									echo "<td>" . htmlentities( $row['node'], ENT_QUOTES ) . "</td>";
									echo "<td>" . htmlentities( $row['target'], ENT_QUOTES ) . "</td>";
									echo "<td>" . htmlentities( $row['fuzzer'], ENT_QUOTES ) . "</td>";
									echo "<td>" . htmlentities( $row['type'], ENT_QUOTES ) . "</td>";
									// small bug here whereby we dont place a * when their are two or more different major crashes (withmatching minor)
									// but one of the unique crashes has more then one instance (logik fail: intval( $row['count'] ) == 1 )
									if( isset( $row['SUM(count)'] ) and intval( $row['SUM(count)'] ) > 1 and intval( $row['count'] ) == 1 )
										echo "<td>" . htmlentities( $row['hash_quick'], ENT_QUOTES ) . ".*</td>";
									else
										echo "<td>" . htmlentities( $row['hash_quick'], ENT_QUOTES ) . "." . htmlentities( $row['hash_full'], ENT_QUOTES ) . "</td>";
									echo "<td>" . htmlentities( $row['time'], ENT_QUOTES ) . "</td>";
									if( isset( $row['SUM(count)'] ) )
										echo "<td>" . htmlentities( $row['SUM(count)'], ENT_QUOTES ) . "</td>";
									else
										echo "<td>" . htmlentities( $row['count'], ENT_QUOTES ) . "</td>";
									echo "</tr>";
								}
								
								echo "</table>";
								
								$total_pages  = intval( $total / $limit ) + 1;
								$current_page = intval( $offset / $limit ) + 1;
								
								echo "<p>";

								if( $current_page > 1 )
								{
									echo "<a title='Go to the first page' href='javascript:_offset(0);'>&lt;&lt;</a> ";
									echo "<a title='Go to the previous page' href='javascript:_offset(" . htmlentities( ( $current_page - 2 ) * $limit, ENT_QUOTES ) . ");'>&lt;</a> ";
								}
								else
								{
									echo "&lt;&lt; &lt; ";
								}
								
								echo "Page " . htmlentities( $current_page, ENT_QUOTES ) . " of " . htmlentities( $total_pages, ENT_QUOTES ) . " ";
								
								if( $current_page < $total_pages )
								{
									echo "<a title='Go to the next page' href='javascript:_offset(" . htmlentities( ( $current_page ) * $limit, ENT_QUOTES ) . ");'>&gt;</a> ";
									echo "<a title='Go to the last page' href='javascript:_offset(" . htmlentities( ( $total_pages - 1 ) * $limit, ENT_QUOTES ) . ");'>&gt;&gt;</a> ";
								}
								else
								{
									echo "&gt; &gt;&gt;";
								}	
								
								echo "</p>";
								
								mysql_free_result( $result );
							}
						}
					?>
					
			<div id='crashes_settings_accordion'>
				<h3><a href="#">Options</a></h3>
				<div>
					<?php
						echo "<p>";
						echo "<input onclick='_unique(this);' type='checkbox' " . ( ( $filter_unique ) ? "checked='checked'" : "" ) . "/>Hide Duplicates. ";
						echo "<input onclick='_owner(this);' type='checkbox' " . ( ( $display_owner ) ? "checked='checked'" : "" ) . "/>Show My Crashes. ";
						echo "</p>";
					?>
				</div>
				<h3><a href="#">Filters</a></h3>
				<div>
					<h3>New Filter</h3>
					<p>Exclude all crashes where the <select id='filter_field_option'><option filter_field='0'>Node</option><option filter_field='1'>Target</option><option filter_field='2'>Fuzzer</option><option filter_field='3'>Type</option><option filter_field='4'>Hash</option><option filter_field='5'>Quick Hash</option><option filter_field='6'>Full Hash</option></select> is equal to <input id='filter_value_input' value=''/><br/><br/><button id='filter_create_button'>Create</button></p>
					
					<h3>All Filters</h3>
					<ul>
					<?php	
						$sql = "SELECT * FROM filters WHERE id='" . mysql_real_escape_string( $_SESSION['id'] ) . "';";
						$result = mysql_query( $sql );
						if( $result )
						{
							$count = 0;
							while( $row = mysql_fetch_array( $result ) )
							{
								$field = $row['field'];
						
								echo "<li><span class='message-text'>Exclude all crashes where the " . htmlentities( $fields[ $field ], ENT_QUOTES ) . " is equal to '" . htmlentities( $row['value'], ENT_QUOTES ) . "'.</span> <button class='delete_filter_button' style='width:30px;height:30px;' title='Delete this filter...' onclick='javascript:_delete_filter_click(" . htmlentities( $row['filter_id'], ENT_QUOTES ) . ");'>&nbsp;</button></li><br/>";
							}
							mysql_free_result( $result );
						}
					?>
					</ul>
				</div>
				<h3><a href="#">Alerts</a></h3>
				<div>
					<h3>New Alert</h3>
					<ul>
						<li><span class='message-text'>Send an e-mail alert upon a new crash where the <select id='alert_field_option'><option alert_field='0'>Node</option><option alert_field='1'>Target</option><option alert_field='2'>Fuzzer</option><option alert_field='3'>Type</option><option alert_field='4'>Hash</option><option alert_field='5'>Quick Hash</option><option alert_field='6'>Full Hash</option></select> is equal to <input id='alert_value_input' value=''/></span><br/><button id='alert_create_button'>Create</button><br/></li>
						<li><span class='message-text'>Send an e-mail alert upon a new unique crash being generated.</span><br/><button id='unique_alert_create_button'>Create</button><br/></li>
						<li><span class='message-text'>Send an e-mail alert upon a new crash being pre verified as interesting or exploitable.</span><br/><button id='verified_alert_create_button'>Create</button><br/></li>
					</ul>
					<h3>All Alerts</h3>
					<ul>
					<?php	
						$sql = "SELECT * FROM alerts WHERE id='" . mysql_real_escape_string( $_SESSION['id'] ) . "';";
						$result = mysql_query( $sql );
						if( $result )
						{
							$count = 0;
							while( $row = mysql_fetch_array( $result ) )
							{
								$field = $row['field'];
						
								if( $fields[ $field ] == 'Unique' )
								{
									echo "<li><span class='message-text'>Send an e-mail alert upon a new crash which is unique.</span> <button class='delete_alert_button' style='width:30px;height:30px;' title='Delete this alert...' onclick='javascript:_delete_alert_click(" . htmlentities( $row['alert_id'], ENT_QUOTES ) . ");'>&nbsp;</button></li><br/>";
								}
								else if( $fields[ $field ] == 'Verified' )
								{
									echo "<li><span class='message-text'>Send an e-mail alert upon a new crash being pre verified as interesting or exploitable.</span> <button class='delete_alert_button' style='width:30px;height:30px;' title='Delete this alert...' onclick='javascript:_delete_alert_click(" . htmlentities( $row['alert_id'], ENT_QUOTES ) . ");'>&nbsp;</button></li><br/>";
								}
								else
								{
									echo "<li><span class='message-text'>Send an e-mail alert upon a new crash where the " . htmlentities( $fields[ $field ], ENT_QUOTES ) . " is equal to '" . htmlentities( $row['value'], ENT_QUOTES ) . "'.</span> <button class='delete_alert_button' style='width:30px;height:30px;' title='Delete this alert...' onclick='javascript:_delete_alert_click(" . htmlentities( $row['alert_id'], ENT_QUOTES ) . ");'>&nbsp;</button></li><br/>";
								}
								
							}
							mysql_free_result( $result );
						}
					?>
					</ul>
				</div>
			</div>
	</body>

</html>

