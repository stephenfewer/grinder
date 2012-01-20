#
# Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
# Licensed under a 3 clause BSD license (Please see LICENSE.txt)
# Source code located at https://github.com/stephenfewer/grinder
#

$:.unshift('.')

require 'core/logging'
require 'rexml/document'

def parse_log_xml( filename )
	document = nil
	
	::File.open( filename, 'r' ) do | f |

		xml = f.read( f.stat.size )

		xml = xml.gsub( '<div>', '&lt;div&gt;' )
		xml = xml.gsub( '<p>', '&lt;p&gt;' )
		xml = xml.gsub( '</p>', '&lt;/p&gt;' )
		xml = xml.gsub( "\n", '' )

		data     = "<?xml version='1.0'?><logs>" + xml + "</logs>"
		document = ::REXML::Document.new( data )
	end

	logs = ::Array.new
	
	document.elements.each do | root |
		next if( root.name.downcase != 'logs' )
		root.each do | element1 |
			next if( element1.name.downcase != 'log' )
			log = ::Hash.new
			element1.each do | element2 |
				if( element2.name == 'idx' )
					log[element2.name] = element2.text.to_i
				elsif( element2.name == 'count' )
					log[element2.name] = element2.text.to_i
				else
					log[element2.name] = element2.text
				end
			end
			logs << log
		end
	end
	
	logs
end

def count_log_idz( logs, count=0 )
	logs.each do | log |
		if( log['message'].include?( 'id_' + count.to_s ) )
			return count_log_idz( logs, count+1 )
		end
	end
	return count - 1
end
	
if( $0 == __FILE__ )

	log_file          = nil
	try_catch         = true
	comment_undefined = false
	print_tickle      = false
	print_comments    = true
	
	skip_elem_id = []
	
	ARGV.each_index do | index |
		case ARGV[index]
			when '+tickle'
				print_tickle = true
			when '-tickle'
				print_tickle = false
			when '+try'
				try_catch = true
			when '-try'
				try_catch = false
			when '+comments'
				print_comments = true	
			when '-comments'
				print_comments = false	
			when '-id_0'
				skip_elem_id << 'id_0'
			when '-id_1'
				skip_elem_id << 'id_1'
			when '-id_2'
				skip_elem_id << 'id_2'
			when '-id_3'
				skip_elem_id << 'id_3'
			when '-id_4'
				skip_elem_id << 'id_4'
			when '-id_5'
				skip_elem_id << 'id_5'
			when '-id_6'
				skip_elem_id << 'id_6'
			when '-id_7'
				skip_elem_id << 'id_7'
			end
	end
	
	log_file = ARGV[ ARGV.length - 1 ]
		
	logs = parse_log_xml( log_file )

	idz  = count_log_idz( logs )

	logs = logs.sort_by do | log |
		log['idx']
	end
	
	print_simple( "<!doctype html>" )
	print_simple( "<html>" )
	print_simple( "\t<head>" )
	print_simple( "\t\t<title>#{log_file}</title>" )
	print_simple( "\t\t<style>" )
	print_simple( "\t\t\tv\:* { behavior: url(#default#VML);}" )
	print_simple( "\t\t</style>" )
	print_simple( "\t\t<script type='text/javascript' src='tickle_and_explore.js'></script>" ) if print_tickle
	print_simple( "\t\t<script>" )
	print_simple( "\t\t\tfunction testcase()" )
	print_simple( "\t\t\t{" )
	print_simple( "\t\t\t\tvar bigbuff = '';" )
	print_simple( "\t\t\t\tvar dynamic_params = [];" )
	print_simple( "\t\t\t\tfor( var b=0 ; b<1111 ; b++ )" )
	print_simple( "\t\t\t\t\tbigbuff += unescape( '%u4141%u4141' );" )
	print_simple( "" )
		
	0.upto( idz ) do | i |
		print_simple( "\t\t\t\tvar id_" + i.to_s + " = null;" )
	end
	
	print_simple( "" )
	
	clone_idx         = 0;
	
	logs.each do | log |
		message = log['message']
		message = message.gsub( '&lt;', '<' )
		message = message.gsub( '&gt;', '>' )
		message = message.gsub( ']( , ', ']( \'\', ' )
		message = message.gsub( ' = ;', ' = \'\';' )
		message = message.gsub( ',  );', ', \'\' );' )
		message = message.gsub( 'BBBB', '\'BBBB\'' )
		message = message.gsub( '<div>', '\'<div>\'' )
		message = message.gsub( 'ohhh<p>no</p>', '\'ohhh<p>no</p>\'' )
		message = message.gsub( '?'*2222, 'bigbuff' )
		
		skip = false
		
		skip_elem_id.each do | elem_id |
			if( message.index( elem_id ) )
				skip = true
				break
			end
		end
		
		if(  message.index( '/*' ) and message.index( '*/' ) )
			skip = true if not print_comments
		end
		
		next if skip
		
		if( message.index('document.createElement') )
			print_simple( "\t\t\t\t" );
		end
		
		if( log['count'] > 1 )
			print_simple( "\t\t\t\tfor( var i=0 ; i<#{log['count']} ; i++ ) {" )
		end
		
		tabs = log['count'] > 1 ? "\t\t\t\t\t" : "\t\t\t\t"
		
		if( message.index('tickle(') and print_tickle )
			print_simple( tabs + "try { " + message[3,message.length-6] + " } catch(e){}" )
		else
			if( try_catch )
				print_simple( "#{tabs}try { #{ message} } catch(e){}" )
			else
				print_simple( "#{tabs}#{message}" )
			end
		end
		
		if( log['count'] > 1 )
			print_simple( "\t\t\t\t}" )
		end
	end
	print_simple( "\t\t\t}" )
	print_simple( "\t\t</script>" )
	print_simple( "\t</head>" )
	print_simple( "\t<body onload='testcase();'>" )
	print_simple( "\t\t<div id='zoo'></div>" )
	print_simple( "\t</body>" )
	print_simple( "</html>" )
	
	::Kernel::exit( true )
end