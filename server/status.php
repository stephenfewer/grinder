<?php
	// Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
	// Licensed under a 3 clause BSD license (Please see LICENSE.txt)
	// Source code located at https://github.com/stephenfewer/grinder
	
	define( 'BASE', true ); 
	
	define( 'NO_SESSION', true ); 
	
	require_once 'config.php';
	
	$verified_unknown       = 0;
	$verified_interesting   = 1;
	$verified_uninteresting = 2;
	$verified_exploitable   = 3;
	
	function update_node_crash_status( $node, $time )
	{
		$success = false;
		
		$sql = "SELECT crashes FROM nodes WHERE name='" . $node . "';";
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
	
	function update_job_status( $node, $version, $time, $testcases_per_minute, $job )
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
	
	function duplicate_crash( $hash )
	{
		$duplicate = false;
		$sql       = "SELECT SUM(count) FROM crashes WHERE hash='" . $hash . "' LIMIT 1;";
		$result    = mysql_query( $sql );
		if( $result )
		{	
			if( mysql_num_rows( $result ) > 0 )
			{
				$row = mysql_fetch_array( $result );
				if( isset( $row['SUM(count)'] ) and intval( $row['SUM(count)'] ) > 0 )
					$duplicate = true;
			}
			mysql_free_result( $result );
		}
		return $duplicate;
	}
	
	function add_crash( $time, $node, $target, $hash_quick, $hash_full, $type, $fuzzer, $log_data, $crash_data, $verified )
	{
		global $verified_interesting, $verified_exploitable;
		
		$success = false;
		
		$hash = $hash_quick . "." . $hash_full;
		
		$unique_crash  = false;
		$unique_before = 0;
		$unique_after  = 0;
		
		$sql    = "SELECT hash_quick FROM crashes GROUP BY hash_quick;";
		$result = mysql_query( $sql );
		if( $result )
		{	
			$unique_before = mysql_num_rows( $result );
			mysql_free_result( $result );
		}
		
		$sql  = "INSERT INTO crashes ( time, node, target, hash, hash_quick, hash_full, type, fuzzer, count, log_data, crash_data, verified ) VALUES ";
		$sql .= "( '" . $time . "', '" . $node . "', '" . $target . "', '" . $hash . "', '" . $hash_quick . "', '" . $hash_full . "', '" . $type . "', '" . $fuzzer . "', '1', '" . $log_data . "', '" . $crash_data . "', '" . $verified . "' );";
		
		$result = mysql_query( $sql );
		if( $result )
		{
			$success = true;
			mysql_free_result( $result );
		
			$sql    = "SELECT hash_quick FROM crashes GROUP BY hash_quick;";
			$result = mysql_query( $sql );
			if( $result )
			{	
				$unique_after = mysql_num_rows( $result );
				mysql_free_result( $result );
			}
		
			if( $unique_after > $unique_before )
				$unique_crash = true;
				
			$sql = "SELECT alerts.field, alerts.value, alerts.id, users.email FROM alerts INNER JOIN users ON alerts.id=users.id WHERE alerts.disabled='0';";
			$result = mysql_query( $sql );
			if( $result )
			{
				$count    = 0;
				$fields   = array( 'Node', 'Target', 'Fuzzer', 'Type', 'Hash', 'Quick Hash', 'Full Hash', 'Unique', 'Verified' );
				$user_ids = array();
				
				while( $row = mysql_fetch_array( $result ) )
				{
					$alert_sent = false;
					$field      = $row['field'];
					
					// we only want to send one email per new crash that matches an alert, even if the new crash would match more then one of the alerts.
					// currently we dont prioritize the alert types.
					if( in_array( $user_ids, $row['id'] ) )
						continue;
						
					//array( 'node', 'target', 'fuzzer', 'type', 'hash', 'hash_quick', 'hash_full', 'unique', 'verified' );
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
						case 7:
							if( $unique_crash )
								$alert_sent = send_alert( $row['email'], 'New Unique Crash', $hash );
							break;
						case 8:
							if( $verified == $verified_interesting )
								$alert_sent = send_alert( $row['email'], 'New Verified Interesting Crash', $hash );
							else if( $verified == $verified_exploitable )
								$alert_sent = send_alert( $row['email'], 'New Verified Exploitable Crash', $hash );
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
				case 'duplicate_crash':
					if( isset($_POST['hash']) )
					{
						$hash = mysql_real_escape_string( trim( $_POST['hash'] ) );

						if( empty( $hash ) or strlen( $hash ) != 17 )
							exit;
							
						$success = duplicate_crash( $hash );
						if( $success )
							header( "duplicate: true" );
						else
							header( "duplicate: false" );
					}
					break;
				case 'update_job_status':
				case 'update_node_fuzz_status':
					if( isset($_POST['time']) && isset($_POST['node']) && isset($_POST['tcpm']) )
					{
						$time                 = mysql_real_escape_string( trim( $_POST['time'] ) );
						$node                 = mysql_real_escape_string( trim( $_POST['node'] ) );
						$testcases_per_minute = intval( mysql_real_escape_string( trim( $_POST['tcpm'] ) ) );
						
						$version = '0.1';
						if( isset($_POST['version']) )
							$version = mysql_real_escape_string( trim( $_POST['version'] ) ); // v0.2 addition

						$job = 'fuzzing';
						if( isset($_POST['job']) )
							$job = mysql_real_escape_string( trim( $_POST['job'] ) ); // v0.3 addition
							
						if( empty( $time ) or empty( $node ) or empty( $version ) or empty( $job ) )
							exit;
							
						$success = update_job_status( $node, $version, $time, $testcases_per_minute, $job );
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
						
						$verified   = $verified_unknown;
						if( isset($_POST['verified']) )
							$verified = intval( mysql_real_escape_string( trim( $_POST['verified'] ) ) ); // v0.2 addition
						
						if( empty( $time ) or empty( $node ) or empty( $target ) or empty( $hash_quick ) or empty( $hash_full ) or empty( $type ) or empty( $fuzzer ) or strlen( $hash_quick ) != 8 or strlen( $hash_full ) != 8 )
							exit;
						
						$log_data   = trim( $_POST['log_data'] );
						$crash_data = trim( $_POST['crash_data'] );

						if( !empty( $log_data ) )
							$log_data = mysql_real_escape_string( base64_encode( base64_decode( strtr( $log_data, '-_,', '+/=' ) ) ) );
						
						if( !empty( $crash_data ) )
							$crash_data = mysql_real_escape_string( base64_encode( base64_decode( strtr( $crash_data, '-_,', '+/=' ) ) ) );
						
						if( $verified < $verified_unknown or $verified > $verified_exploitable )
							$verified = $verified_unknown;
							
						$success = add_crash( $time, $node, $target, $hash_quick, $hash_full, $type, $fuzzer, $log_data, $crash_data, $verified );
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
