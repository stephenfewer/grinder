#
# Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
# Licensed under a 3 clause BSD license (Please see LICENSE.txt)
# Source code located at https://github.com/stephenfewer/grinder
#

require 'net/http'
require 'uri'
require 'core/logging'
require 'base64'

module Grinder

	module Core
	
		class WebStats
		
			def initialize( node, baseurl, key, username=nil, password=nil, https=false )
			    @node     = node
			    @baseurl  = baseurl
				@key      = key
				@username = username
				@password = password
				@https    = https
			end
			
			def update_node_fuzz_status( testcases_per_minute )
				
				params = {
					'key'    => @key,
					'action' => 'update_node_fuzz_status',
					'time'   => ::Time.new.strftime( "%Y-%m-%d %H:%M:%S" ),
					'node'   => @node,
					'tcpm'   => testcases_per_minute
				}

				return _send_request( params )
			end
			
			def add_crash( time, browser, hash, type, fuzzer, crash_data, log_data )
			
				params = {
					'key'        => @key,
					'action'     => 'add_crash',
					'time'       => time,
					'node'       => @node,
					'browser'    => browser,
					'hash_quick' => hash[0],
					'hash_full'  => hash[1],
					'type'       => type,
					'fuzzer'     => fuzzer,
					'crash_data' => ::Base64.encode64( crash_data ).tr( '+/=', '-_,' ).gsub( "\n", '' ),
					'log_data'   => ::Base64.encode64( log_data ).tr( '+/=', '-_,' ).gsub( "\n", '' )
				}

				return _send_request( params )
			end
			
			protected
			
			def _send_request( params )
			
				uri = ::URI.parse( "#{ @https ? 'https' : 'http' }://#{@baseurl}" )
				
				http = ::Net::HTTP.new( uri.host, uri.port )

				if( @https )
					http.use_ssl = true
					# XXX: Currently we don't enforce certificate verification...
					http.verify_mode = OpenSSL::SSL::VERIFY_NONE
				end
				
				request = ::Net::HTTP::Post.new( uri.request_uri )
				
				if( @username and @password )
					request.basic_auth( @username, @password )
				end
				
				request.set_form_data( params )
				
				response = http.request( request )

				if( response.code.to_i == 200 )
					return true
				end
				
				return false
			end
			
		end
		
	end
	
end

if( $0 == __FILE__ )
	
	require 'core/configuration'
	require 'core/crypt'
	
	config_file = 'config'
	
	ARGV.each do | arg |
		if( arg.include?( '--config=' ) )
			config_file = arg[9,arg.length]
		end
	end
	
	if( not config_init( config_file ) )
		print_error( "Failed to load the config file '#{config_file}'." )
		::Kernel::exit( false )
	end	

	crash_data = 'ABCD' * 4096
	log_data   = '1234' * 1024

	if( $crashes_encrypt )
		public_key = OpenSSL::PKey::RSA.new( ::File.read( $public_key_file ) )
		crash_data = Grinder::Core::Crypt.encrypt( public_key, crash_data )	
		log_data   = Grinder::Core::Crypt.encrypt( public_key, log_data )
	end
	
	web = ::Grinder::Core::WebStats.new( $grinder_node, $webstats_baseurl, $webstats_key, $webstats_username, $webstats_password, $webstats_https )

	success = web.add_crash( ::Time.new.strftime( "%Y-%m-%d %H:%M:%S" ), $grinder_node, ['ABABABAB','12121212'], 'Testing', 'TestFuzzer', crash_data, log_data )
	
	$stdout.puts success
	
end