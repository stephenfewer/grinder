/*
 * Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
 * Licensed under a 3 clause BSD license (Please see LICENSE.txt)
 * Source code located at https://github.com/stephenfewer/grinder
 * 
 */
 
function rand( x )
{
	return Math.floor( Math.random() * x );
}

function rand_bool()
{
	return ( rand( 2 ) == 1 ? true : false );
}

function rand_item( arr )
{
	return arr[ rand( arr.length ) ];
}

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

function LOGGER( name )
{
	this.name    = name;
	this.browser = '';
	
	idx          = 0;
	unique_types = [];
	
	this.get_browser = function()
	{
		if( /Firefox[\/\s](\d+\.\d+)/.test(navigator.userAgent) )
			return "FF";
		else if( /MSIE (\d+\.\d+);/.test(navigator.userAgent) )
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
	
	this.browser = this.get_browser();
	
	this.starting = function()
	{
		parseFloat( unescape( '%uBEEF%uDEAD') + '<fuzzer name="' + this.name + '" browser="' + this.browser + '">' );
	};
	
	this.unique_id = function( type )
	{
		if( typeof unique_types[type] == 'undefined' )
			unique_types[type] = 0;
			
		var result = type + '_' + unique_types[type];

		unique_types[type] += 1;

		return result;
	};
	
	if( this.browser == 'CM' || this.browser == 'FF' || this.browser == 'SF' )
	{
		this.log = function( message, location, count )
		{
			idx += 1;

			message = message.replace( /</g, "&lt;" );
			message = message.replace( />/g, "&gt;" );
			message = message.replace( /&/g, "&amp;" );
			message = message.replace( /\"/g, "&quot;" );
			message = message.replace( /\'/g, "&apos;" );

			log_xml  = '<log name="' + this.name + '" browser="' + this.browser + '">';
			log_xml += '<idx>' + idx + '</idx>';
			log_xml += '<location>' + location + '</location>';
			log_xml += '<message>' + message + '</message>';
			log_xml += '<count>' + count + '</count>';
			log_xml += '</log>';

			parseFloat( unescape( '%uC0DE%uDEAD'+log_xml+'%u0000' ) );
			
			return idx - 1;
		};

		this.finished = function()
		{
			parseFloat( unescape( '%uF00D%uDEAD' + '</fuzzer>' + '%u0000' )  );
		};
	}
	else
	{
		this.log = function( message, location, count )
		{
			idx += 1;
			
			message = message.replace( /</g, "&lt;" );
			message = message.replace( />/g, "&gt;" );
			message = message.replace( /&/g, "&amp;" );
			message = message.replace( /\"/g, "&quot;" );
			message = message.replace( /\'/g, "&apos;" );
			
			log_xml  = '<log name="' + this.name + '" browser="' + this.browser + '">';
			log_xml += '<idx>' + idx + '</idx>';
			log_xml += '<location>' + location + '</location>';
			log_xml += '<message>' + message + '</message>';
			log_xml += '<count>' + count + '</count>';
			log_xml += '</log>';

			parseFloat( unescape( '%uC0DE%uDEAD') + log_xml );
			
			return idx - 1;
		};

		this.finished = function()
		{
			parseFloat( unescape( '%uF00D%uDEAD') + '</fuzzer>' );
		};
	}
	
	this.type = function( name, obj, obj_hint )
	{
		if( typeof obj_hint == 'undefined' )
		{
			var id = "?";

			try
			{
				if( typeof obj.id != 'undefined' )
					return obj.id;
				id = obj.id;
			} catch(e){}
	
			obj_hint = "%" + name + "," + id + "%";
		}

		return obj_hint;
	};
}
