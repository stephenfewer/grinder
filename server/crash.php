<?php
	// Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
	// Licensed under a 3 clause BSD license (Please see LICENSE.txt)
	// Source code located at https://github.com/stephenfewer/grinder
	
	define( 'BASE', true );
	
	require_once 'config.php';
	
	require_once 'user.php';
	
	if( !user_isloggedin() )
		exit;
		
	function update_crash( $id, $notes, $verified, $owner_id )
	{
		$sql = "UPDATE crashes SET notes='" . $notes . "', verified='" . $verified . "', owner_id='" . $owner_id . "'  WHERE id='" . $id . "' LIMIT 1;";
		
		if( !mysql_query( $sql ) )
			return false;
		
		return true;
	}
	
	function delete_crash( $id )
	{
		// XXX: we need to minus one from the respective nodes crashes
		/*$sql = "DELETE FROM crashes WHERE id='" . $id . "' LIMIT 1;";
		
		if( !mysql_query( $sql ) )
			return false;
		*/
		return true;
	}

	function get_crash_data( $id )
	{
		$data   = '';
		$sql    = "SELECT crash_data FROM crashes WHERE id='" . $id . "' LIMIT 1;";
		$result = mysql_query( $sql );
		if( $result )
		{
			if( mysql_num_rows( $result ) == 1 )
			{
				$row  = mysql_fetch_array( $result );

				$data = base64_decode( $row['crash_data'] );
			}
			mysql_free_result( $result );
		}
		
		return $data;
	}
	
	function get_log_data( $id )
	{
		$data   = '';
		$sql    = "SELECT log_data FROM crashes WHERE id='" . $id . "' LIMIT 1;";
		$result = mysql_query( $sql );
		if( $result )
		{
			if( mysql_num_rows( $result ) == 1 )
			{
				$row  = mysql_fetch_array( $result );

				$data = base64_decode( $row['log_data'] );
			}
			mysql_free_result( $result );
		}
		return $data;
	}
	
	if( $_SERVER['REQUEST_METHOD'] == 'GET' )
	{
		if( isset( $_GET['action'] ) )
		{
			$action = mysql_real_escape_string( $_GET['action'] );

			switch( $action )
			{
				case 'get_crash_data':
					if( isset($_GET['id']) and isset($_GET['filename']) )
					{
						$id       = intval( mysql_real_escape_string( trim( $_GET['id'] ) ) );
						$filename = mysql_real_escape_string( trim( $_GET['filename'] ) );
						
						$data = get_crash_data( $id );
						if( !empty( $data ) )
						{
							header( 'Content-Disposition: attachment; filename=' . $filename . '' );
							header( 'Content-Type: text/plain' );
							echo $data;
							exit;
						}
					}
					break;
				case 'get_log_data':
					if( isset($_GET['id']) and isset($_GET['filename']) )
					{
						$id       = intval( mysql_real_escape_string( trim( $_GET['id'] ) ) );
						$filename = mysql_real_escape_string( trim( $_GET['filename'] ) );
						
						$data = get_log_data( $id );
						if( !empty( $data ) )
						{
							header( 'Content-Disposition: attachment; filename=' . $filename . '' );
							header( 'Content-Type: text/plain' );
							echo $data;
							exit;
						}
					}
					break;
				default:
					break;
			}
			
			header( 'HTTP/1.0 404 Not Found' );
			exit;
		}
	}
	else if( $_SERVER['REQUEST_METHOD'] == 'POST' )
	{
		if( isset( $_POST['action'] ) )
		{
			$success = false;
			
			$action = mysql_real_escape_string( $_POST['action'] );

			switch( $action )
			{
				case 'update':
					if( isset($_POST['id']) && isset($_POST['notes']) && isset($_POST['verified']) && isset($_POST['owner_id']) )
					{
						$id       = intval( mysql_real_escape_string( trim( $_POST['id'] ) ) );
						$notes    = mysql_real_escape_string( trim( $_POST['notes'] ) );
						$verified = intval( mysql_real_escape_string( trim( $_POST['verified'] ) ) );
						$owner_id = intval( mysql_real_escape_string( trim( $_POST['owner_id'] ) ) );
						
						$success = update_crash( $id, $notes, $verified, $owner_id );
					}
					break;
				case 'delete':
					if( isset($_POST['id'])  )
					{
						$id = intval( mysql_real_escape_string( trim( $_POST['id'] ) ) );
						
						$success = delete_crash( $id );
					}
					break;
				default:
					break;
			}
			
			if( $success )
				header( 'HTTP/1.0 200 OK' );
			else
				header( 'HTTP/1.0 404 Not Found' );
			
			exit;
		}
	}
?>

<!DOCTYPE html>
<html>

	<body>
		<script>
			$(function() {
				$( 'button' ).button();
			});
			
			function deleteCrash()
			{
				if( confirm( 'Are you really sure you want to delete this crash?' ) )
				{
					$.post( 'crash.php', { action:'delete', id:getID }, function( data ) {
						$( '#crash-dialog' ).dialog( 'close' );
						refreshTab( 1 );
					});
				}
			}
			
			function updateCrash()
			{
				$.post( 'crash.php', { action:'update', id:getID, notes:getNotes, verified:getVerified, owner_id:getOwnerId }, function( data ) {
					$( '#crash-dialog' ).dialog( 'close' );
					refreshTab( 1 );
				});
			}

			function getNotes()
			{
				return document.getElementById('crash_notes').value;
			}
			
			function getVerified() 
			{
				return document.getElementById('crash_verified').selectedIndex;
			}
			
			function getOwnerId() 
			{
				var crash_owner = document.getElementById( 'crash_owner' );
				
				var option = crash_owner.options[ crash_owner.selectedIndex ];
				
				return option.getAttribute( 'owner_id' );
			}
		</script>

		<div id='details'>
			<h2>Details</h2>
			<table width='100%' border='0' cellspacing='10' cellpadding='0'>
				<?php
					$node              = '';
					$target            = '';
					$fuzzer            = '';
					$type              = '';
					$hash_quick        = '';
					$hash_full         = '';
					$time              = '';
					$verified          = '';
					$notes             = '';
					$id                = 0;
					$owner_id          = 0;
					$log_data_length   = 0;
					$crash_data_length = 0;
					
					if( isset( $_POST['id'] ) )
						$id = intval( mysql_real_escape_string( $_POST['id'] ) );
						
					$sql = "SELECT *, length(log_data), length(crash_data) FROM crashes WHERE id='" . mysql_real_escape_string( $id ) . "';";
					
					$result = mysql_query( $sql );
					if( $result )
					{
						$row = mysql_fetch_array( $result );
						if( $row )
						{
							$node              = $row['node'];
							$target            = $row['target'];
							$fuzzer            = $row['fuzzer'];
							$type              = $row['type'];
							$hash_quick        = $row['hash_quick'];
							$hash_full         = $row['hash_full'];
							$time              = $row['time'];
							$verified          = $row['verified'];
							$notes             = $row['notes'];
							$owner_id          = $row['owner_id'];
							$log_data_length   = intval( $row['length(log_data)'] );
							$crash_data_length = intval( $row['length(crash_data)'] );
						}
						else
						{
							mysql_free_result( $result );
							exit;
						}
						
						mysql_free_result( $result );
					}
					else
					{
						exit;
					}
			
					echo "<script>function getID() { return " . htmlentities( $id, ENT_QUOTES ) . "; }</script>";

					echo "<tr><td>Node: " . htmlentities( $node, ENT_QUOTES ) . "</td><td>Target: " . htmlentities( $target, ENT_QUOTES ) . "</td></tr>";
							
					echo "<tr><td>Fuzzer: " . htmlentities( $fuzzer, ENT_QUOTES ) . "</td><td>Type: " . htmlentities( $type, ENT_QUOTES ) . "</td></tr>";
							
					echo "<tr><td>Hash: " . htmlentities( $hash_quick, ENT_QUOTES ) . "." . htmlentities( $hash_full, ENT_QUOTES ) . "</td><td>Date: " . htmlentities( $time, ENT_QUOTES ) . "</td></tr>";
				?>
				
				<tr><td>Verified: 
					<select id='crash_verified'>
						<option <?php if( $verified == 0 ){ echo 'selected="selected"'; } ?> >Unknown</option>
						<option <?php if( $verified == 1 ){ echo 'selected="selected"'; } ?> >Interesting</option>
						<option <?php if( $verified == 2 ){ echo 'selected="selected"'; } ?> >Uninteresting</option>
						<option <?php if( $verified == 3 ){ echo 'selected="selected"'; } ?> >Exploitable</option>
					</select></td>
					
				<?php
					echo "<td>Owner: <select id='crash_owner'>";
							
					echo "<option owner_id='0'";
					if( $row['id'] == 0 )
						echo "selected='selected'";
					echo "></option>";
							
					$sql = "SELECT id, name FROM users;";
					$result = mysql_query( $sql );
					if( $result )
					{
						while( $row = mysql_fetch_array( $result ) )
						{
							echo "<option owner_id='" . htmlentities( $row['id'], ENT_QUOTES ) . "'";
							if( $owner_id == $row['id'] )
								echo "selected='selected'";
							echo ">" . htmlentities( $row['name'] ) . "</option>";
						}
						mysql_free_result( $result );
					}
					
					echo "</select></td></tr>";
				?>
				
			</table>
		</div>
		
		<div id='files'>
			<h2>Files</h2>
			
			<?php
				$filename = htmlentities( $hash_quick, ENT_QUOTES ) . '.' . htmlentities( $hash_full, ENT_QUOTES ) . '.crash';
				
				echo "<a target='_blank' href='crash.php?action=get_crash_data&id=" . htmlentities( $id, ENT_QUOTES ) . "&filename=" . $filename ."'>" . $filename . "</a> (" . htmlentities( $crash_data_length, ENT_QUOTES ) . " bytes)";
				
				echo " ";
				
				$filename = htmlentities( $hash_quick, ENT_QUOTES ) . '.' . htmlentities( $hash_full, ENT_QUOTES ) . '.log';
				
				echo "<a target='_blank' href='crash.php?action=get_log_data&id=" . htmlentities( $id, ENT_QUOTES ) . "&filename=" . $filename ."'>" . $filename . "</a>(" . htmlentities( $log_data_length, ENT_QUOTES ) . " bytes)";
			?>
			
		</div>
		
		<div id='notes'>
			<h2>Notes</h2>
			<textarea id='crash_notes'><?php echo htmlentities( $notes, ENT_QUOTES ); ?></textarea>
		</div>

	</body>
	
</html>