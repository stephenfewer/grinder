<?php
	// Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
	// Licensed under a 3 clause BSD license (Please see LICENSE.txt)
	// Source code located at https://github.com/stephenfewer/grinder
	
	define( 'BASE', true ); 
	
	define( 'NO_SESSION', true ); 
	
	require_once 'config.php';
	
	function update_node_crash_status( $node, $time )
	{
		$success = false;
		
		$sql = "SELECT * FROM nodes WHERE name='" . $node . "';";
		$result = mysql_query( $sql );
		if( $result )
		{
			if( mysql_num_rows( $result ) == 0 )
			{
				// add in new node...
				$sql = "INSERT INTO nodes ( name, crashes, lastcrash, lastfuzz, testcases_per_minute ) VALUES ( '" . $node . "', '1', '" . $time . "', '', '0' );";
				$result2 = mysql_query( $sql );
				if( $result2 )
				{
					$success = true;
					mysql_free_result( $result2 );
				}
			}
			else
			{
				// update existing node...
				$row = mysql_fetch_array( $result );
				if( $row )
				{
					$crashes = intval( $row['crashes'] ) + 1;
					
					$sql = "UPDATE nodes SET crashes='" . $crashes . "', lastcrash='" . $time . "' WHERE name='" . $node . "';";
					$result2 = mysql_query( $sql );
					if( $result2 )
					{
						$success = true;
						mysql_free_result( $result2 );
					}
				}
			}
			
			mysql_free_result( $result );
		}
		
		return $success;
	}
	
	function update_node_fuzz_status( $node, $time, $testcases_per_minute )
	{
		$success = false;
		
		$sql = "SELECT lastfuzz FROM nodes WHERE name='" . $node . "';";
		$result = mysql_query( $sql );
		if( $result )
		{
			if( mysql_num_rows( $result ) == 0 )
			{
				// add in new node...
				$sql = "INSERT INTO nodes ( name, crashes, lastcrash, lastfuzz, testcases_per_minute ) VALUES ( '" . $node . "', '0', '', '" . $time . "', '" . $testcases_per_minute . "' );";
				$result2 = mysql_query( $sql );
				if( $result2 )
				{
					$success = true;
					mysql_free_result( $result2 );
				}
			}
			else
			{
				// update existing node...
				$sql = "UPDATE nodes SET testcases_per_minute='" . $testcases_per_minute . "', lastfuzz='" . $time . "'  WHERE name='" . $node . "';";
				$result2 = mysql_query( $sql );
				if( $result2 )
				{
					$success = true;
					mysql_free_result( $result2 );
				}
			}
			mysql_free_result( $result );
		}

		return $success;
	}
	
	function send_alert( $email, $field, $value )
	{
		$message = "A crash has triggered an alert for a '" . htmlentities( $field, ENT_QUOTES ) . "' equal to '" . htmlentities( $value, ENT_QUOTES ) . "'.\n\n";

		return mail( $email, "Grinder: Alert!", $message ); 
	}
	
	function add_crash( $time, $node, $target, $hash_quick, $hash_full, $type, $fuzzer, $log_data, $crash_data )
	{
		$success = false;
		
		$hash = $hash_quick . "." . $hash_full;
		
		$sql  = "INSERT INTO crashes ( time, node, target, hash, hash_quick, hash_full, type, fuzzer, count, log_data, crash_data ) VALUES ";
		$sql .= "( '" . $time . "', '" . $node . "', '" . $target . "', '" . $hash . "', '" . $hash_quick . "', '" . $hash_full . "', '" . $type . "', '" . $fuzzer . "', '1', '" . $log_data . "', '" . $crash_data . "' );";
				
		$result = mysql_query( $sql );
		if( $result )
		{
			$success = true;
			mysql_free_result( $result );
			
			$sql = "SELECT alerts.field, alerts.value, alerts.id, users.email FROM alerts INNER JOIN users ON alerts.id=users.id WHERE alerts.disabled='0';";
			$result = mysql_query( $sql );
			if( $result )
			{
				$count    = 0;
				$fields   = array( 'Node', 'Target', 'Fuzzer', 'Type', 'Hash', 'Quick Hash', 'Full Hash' );
				$user_ids = array();
				
				while( $row = mysql_fetch_array( $result ) )
				{
					$alert_sent = false;
					$field      = $row['field'];
					
					if( in_array( $user_ids, $row['id'] ) )
						continue;
						
					//array( 'node', 'target', 'fuzzer', 'type', 'hash', 'hash_quick', 'hash_full' );
					switch( $field )
					{
						case 0:
							if( $node == $row['value'] )
								$alert_sent = send_alert( $row['email'], $fields[$field], $row['value'] );
							break;
						case 1:
							if( $target == $row['value'] )
								$alert_sent = send_alert( $row['email'], $fields[$field], $row['value'] );
							break;
						case 2:
							if( $fuzzer == $row['value'] )
								$alert_sent = send_alert( $row['email'], $fields[$field], $row['value'] );
							break;
						case 3:
							if( $type == $row['value'] )
								$alert_sent = send_alert( $row['email'], $fields[$field], $row['value'] );
							break;
						case 4:
							if( $hash == $row['value'] )
								$alert_sent = send_alert( $row['email'], $fields[$field], $row['value'] );
							break;
						case 5:
							if( $hash_quick == $row['value'] )
								$alert_sent = send_alert( $row['email'], $fields[$field], $row['value'] );
							break;
						case 6:
							if( $hash_full == $row['value'] )
								$alert_sent = send_alert( $row['email'], $fields[$field], $row['value'] );
							break;
						default:
							break;
					}
					
					if( $alert_sent )
						array_push( $user_ids, $row['id'] );
				}
				
				mysql_free_result( $result );
			}		
		}
		
		if( $success )
			$success = update_node_crash_status( $node, $time );

		return $success;
	}
	
	$success = false;
	
	if( $_SERVER['REQUEST_METHOD'] == 'POST' )
	{
	
		if( isset( $_POST['key'] ) && isset( $_POST['action'] ) )
		{
			$key    = mysql_real_escape_string( trim( $_POST['key'] ) );
			$action = mysql_real_escape_string( trim( $_POST['action'] ) );
			
			if( $key != GRINDER_KEY )
			{
				exit;
			}

			switch( $action )
			{
				case 'update_node_fuzz_status':
					if( isset($_POST['time']) && isset($_POST['node']) && isset($_POST['tcpm']) )
					{
						$time                 = mysql_real_escape_string( trim( $_POST['time'] ) );
						$node                 = mysql_real_escape_string( trim( $_POST['node'] ) );
						$testcases_per_minute = intval( mysql_real_escape_string( trim( $_POST['tcpm'] ) ) );
						
						if( empty( $time ) or empty( $node ) )
							exit;
							
						$success = update_node_fuzz_status( $node, $time, $testcases_per_minute );
					}
					break;
				case 'add_crash':
					if( isset($_POST['time']) && isset($_POST['node']) && isset($_POST['browser']) && isset($_POST['hash_quick']) && isset($_POST['hash_full']) && isset($_POST['fuzzer']) && isset($_POST['type']) && isset($_POST['log_data']) && isset($_POST['crash_data']) )
					{
						$time       = mysql_real_escape_string( trim( $_POST['time'] ) );
						$node       = mysql_real_escape_string( trim( $_POST['node'] ) );
						$target     = mysql_real_escape_string( trim( $_POST['browser'] ) );
						$hash_quick = mysql_real_escape_string( trim( $_POST['hash_quick'] ) );
						$hash_full  = mysql_real_escape_string( trim( $_POST['hash_full'] ) );
						$type       = mysql_real_escape_string( trim( $_POST['type'] ) );
						$fuzzer     = mysql_real_escape_string( trim( $_POST['fuzzer'] ) );
						
						if( empty( $time ) or empty( $node ) or empty( $target ) or empty( $hash_quick ) or empty( $hash_full ) or empty( $type ) or empty( $fuzzer ) or strlen( $hash_quick ) != 8 or strlen( $hash_full ) != 8 )
							exit;
						
						$log_data   = trim( $_POST['log_data'] );
						$crash_data = trim( $_POST['crash_data'] );

						if( !empty( $log_data ) )
							$log_data = mysql_real_escape_string( base64_encode( base64_decode( strtr( $log_data, '-_,', '+/=' ) ) ) );
						
						if( !empty( $crash_data ) )
							$crash_data = mysql_real_escape_string( base64_encode( base64_decode( strtr( $crash_data, '-_,', '+/=' ) ) ) );
						
						$success = add_crash( $time, $node, $target, $hash_quick, $hash_full, $type, $fuzzer, $log_data, $crash_data );
					}
					break;
				default:
					exit;
			}
			

			
		}
	}
			
	if( $success )
		header( 'HTTP/1.0 200 OK' );
	else
		header( 'HTTP/1.0 404 Not Found' );
		
	exit();
?>
