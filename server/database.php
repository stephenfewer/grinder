<?php
	// Copyright (c) 2014, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
	// Licensed under a 3 clause BSD license (Please see LICENSE.txt)
	// Source code located at https://github.com/stephenfewer/grinder
	
	function database_get_name()
	{
		$name   = '';
		$result = mysql_query( "SELECT DATABASE()" );
		if( $result )
		{
			$name = mysql_result( $result, 0 );
			
			mysql_free_result( $result );
		}
		return $name;
	}
	
	function database_purge()
	{
		$success = false;
		
		mysql_query( "START TRANSACTION;" );
		
		do
		{
			if( !mysql_query( "DELETE FROM crashes;" ) )
				break;

			if( !mysql_query( "DELETE FROM nodes;" ) )
				break;
				
			$success = true;
			
		} while( 0 );
		
		if( $success )
			mysql_query( "COMMIT;" );
		else
			mysql_query( "ROLLBACK;" );
			
		return $success;
	}

?>