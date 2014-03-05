/*
 * Copyright (c) 2014, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
 * Licensed under a 3 clause BSD license (Please see LICENSE.txt)
 * Source code located at https://github.com/stephenfewer/grinder
 * 
 */

// Pick a random number between 0 and X
function rand( x )
{
	return Math.floor( Math.random() * x );
}

// Pick either true or false
function rand_bool()
{
	return ( rand( 2 ) == 1 ? true : false );
}

// Pick an item from an array
function rand_item( arr )
{
	return arr[ rand( arr.length ) ];
}

// Iterate over an object to simulate 'tickling' the object. This is useful during
// testcase creating/reduction in order to trigger the original crash. If you comment
// your fuzzer with log code comments of "/* tickle( OBJ ); */" then these comments
// can be removed to tickle the object. Use where you iterate over an object looking
// for a property/function/...
function tickle( obj )
{
	try
	{
		for( var p in obj )
		{
			try { var tmp = typeof obj[p]; } catch( e2 ){}
		}
	}
	catch( e1 ){}
}

// The logger class used to perform in-memory logging from a fuzzer.
// This is linked with the back end via the injected grinder_logger.dll which
// will hook the JavaScript parseFloat function and intercept any messages
// passed in by the logger class and write them to disk.
function LOGGER( name )
{
	this.name        = name;
	this.browser     = '';
	
	var idx          = 0;
	var unique_types = [];
	var log_xml      = null;
	var log_xml_idx  = null;
	
	this.gc = function()
	{
		if( this.browser == 'IE' )
		{
			CollectGarbage();
		}
		else if( this.browser == 'CM' )
		{
			if( typeof window.gc != 'undefined' )
			{
				window.gc();
			}
			else
			{
				for( f=[], i=0 ; i<30000 ; i++ )
					f.push( new String( "ABCD" ) );
			}
		}
		/*else
		{
		    for( i=0; i < 10000; i++ )
				var s = new String( unescape( '%u7F7F%u7F7F' ) );
		}*/
	};
	
	this.get_browser = function()
	{
		if( /Firefox[\/\s](\d+\.\d+)/.test(navigator.userAgent) )
			return "FF";
		else if( /MSIE (\d+\.\d+);/.test(navigator.userAgent) )
			return "IE";
		else if( /Trident\//.test(navigator.userAgent) )
			return "IE";
		else if( /Chrome/.test(navigator.userAgent) )
			return "CM";
		else if( /Safari/.test(navigator.userAgent) )
			return "SF";
		else if( /Opera/.test(navigator.userAgent) )
			return "OP";
		else
			return "??";
	};
	
	// Access this instance variable to get the browser...
	this.browser = this.get_browser();

	if( this.browser == 'CM' || this.browser == 'FF' || this.browser == 'SF' )
	{
		log_xml = function( xml )
		{
			parseFloat( unescape( '%uC0DE%uDEAD' + xml + '%u0000' ) );
		};

		log_xml_idx = function( xml, _idx )
		{
			parseFloat( unescape( '%uCAFE%uDEAD' + dword2data( _idx ) + xml + '%u0000' ) );
		};
		
		// You call this to indicate logging is starting...
		this.starting = function()
		{
			parseFloat( unescape( '%uBEEF%uDEAD' + '<fuzzer name="' + xml_escape( this.name ) + '" browser="' + xml_escape( this.browser ) + '">' + '%u0000' ) );
		};
		
		// You call this to indicate logging is finished...
		this.finished = function()
		{
			parseFloat( unescape( '%uF00D%uDEAD' + '</fuzzer>' + '%u0000' ) );
		};
		
		// You call this to trigger an access violation (attempted write to a bad address)...
		this.debugbreak = function()
		{
			parseFloat( unescape( '%uDEAD%uDEAD' + '%u0000' ) );
		};
	}
	else
	{
		log_xml = function( xml )
		{
			parseFloat( unescape( '%uC0DE%uDEAD') + xml );
		};
		
		log_xml_idx = function( xml, _idx )
		{
			parseFloat( unescape( '%uCAFE%uDEAD') + dword2data( _idx ) + xml );
		};
		
		this.starting = function()
		{
			parseFloat( unescape( '%uBEEF%uDEAD') + '<fuzzer name="' + xml_escape( name ) + '" browser="' + xml_escape( this.browser ) + '">' );
		};
		
		this.finished = function()
		{
			parseFloat( unescape( '%uF00D%uDEAD') + '</fuzzer>' );
		};
		
		this.debugbreak = function()
		{
			parseFloat( unescape( '%uDEAD%uDEAD' ) );
		};
	}
	
	// Call this instance method to generate a unique name for a type, e.g.
	//     The first call to unique_id( 'id' ) will first produce 'id_0'
	//     A second call to unique_id( 'id' ) will then produce 'id_1'
	//     A subsequent call to unique_id( 'param' ) will produce 'param_0'
	//     ...and so on...
	this.unique_id = function( type )
	{
		if( typeof unique_types[type] == 'undefined' )
			unique_types[type] = 0;
			
		var result = type + '_' + unique_types[type];

		unique_types[type] += 1;

		return result;
	};
	
	// Call this instance method to retrieve a random id of a previous type.
	this.rand_id = function( type )
	{
		if( typeof unique_types[type] == 'undefined' )
			unique_types[type] = 0;
		
		return type + '_' + rand( unique_types[type] );
	};
	
	// Call this instance method to retrieve the number of ID's of this type
	this.count_id = function( type )
	{
		if( typeof unique_types[type] == 'undefined' )
			return 0;
		
		return unique_types[type];
	};
	
	// Used to log a message from the fuzzer to the log file on disk. This is how we recreate testcases at a later stage.
	// You must log the JavaScript lines of code you wish to record. The message parameter is a string containing a line
	// of JavaScript. The location string parameter is optional, and can describe where in your fuzzer this log message came from.
	// The count number parameter is optional and defines how many times to execute the log message when recreating the testcase.
	// Note: Currently only logging string messages is supported, but future support for logging nested messages via an array
	// of string messages will be supported at a later stage.
	//
	// You can log a line of JavaScript as follows: logger.log( "id_0.src = 'AAAAAAAA';", "tweak_params", 8 );
	// When recreating a testcase this will produce the following (optionally surrounded by a try/catch statement):
	//     for( i=0 ; i<8 ; i++ ) {
	//         id_0.src = 'AAAAAAAA';
	//     }
	//
	// The for() loop is never emitted if you log a count value of 1.
	//
	// You can log code comments as follows: logger.log( "/* tickle( id_0 ); */", "tweak_params" );
	// When recreating a testcase the code comment will be written as a code comment by default, but also may be uncommented 
	// in order to execute the javascript inside the comment as this may help recreate the crash.
	//
	// You can log regular comments a follows: logger.log( "// This is a message to myself :)" );
	// These will simply be printed as a comment in the testcase and will never be uncommented.
	//
	this.log = function( message, location, count )
	{
		var last_idx = -1;
		
		if( typeof location != 'string' )
			location = '';
		
		if( typeof count != 'number' )
			count = 1;
			
		if( typeof message == 'string' )
		{
			last_idx = log_message( message, location, count );
		}
		else
		{
			if( typeof message.length != 'undefined' && message.length > 0 )
			{
				idx += 1;
				
				xml  = '<log>';
				xml += '<idx>' + idx + '</idx>';
				xml += '<location>' + xml_escape( location ) + '</location>';
				xml += '<count>' + count + '</count>';

				log_xml_idx( xml, idx );
			
				for( var m in message )
					last_idx = this.log( message[m], location, 1 );

				log_xml( '</log>' );
			}
		}
		
		return last_idx;
	};
	
	var xml_escape = function( message )
	{
		message = message.replace( /</g, "&lt;" );
		message = message.replace( />/g, "&gt;" );
		message = message.replace( /&/g, "&amp;" );
		message = message.replace( /\"/g, "&quot;" );
		message = message.replace( /\'/g, "&apos;" );
		
		return message;
	};
	
	var log_message = function( message, location, count )
	{
		idx += 1;
		
		xml  = '<log>';
		xml += '<idx>' + idx + '</idx>';
		xml += '<location>' + xml_escape( location ) + '</location>';
		xml += '<message>' + xml_escape( message ) + '</message>';
		xml += '<count>' + count + '</count>';
		xml += '</log>';

		log_xml_idx( xml, idx );
		
		return idx - 1;
	};
	
	var dword2data = function( dword )
	{
		var d = Number( dword ).toString( 16 );
		while( d.length < 8 )
			d = '0' + d;
		return unescape( '%u' + d.substr( 4, 8 ) + '%u' + d.substr( 0, 4 ) );
	};
	
	this.type = function( name, obj, obj_hint )
	{
		if( typeof obj_hint == 'undefined' )
		{
			var id = "?";

			try
			{
				if( typeof obj.id != 'undefined' )
					return obj.id;
			} catch(e){}
	
			obj_hint = "%" + name + "%";
		}

		return obj_hint;
	};
}
