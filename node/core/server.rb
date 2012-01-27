#
# Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
# Licensed under a 3 clause BSD license (Please see LICENSE.txt)
# Source code located at https://github.com/stephenfewer/grinder
#

require 'thread'
require 'webrick'
require 'base64'
require 'core/logging'
require 'core/webstats'

module Grinder

	module Core

		class Server
			
			class NoLog < ::WEBrick::BasicLog
				def log( level, data ) end
			end
			
			class GrinderServlet < WEBrick::HTTPServlet::AbstractServlet

				@@fuzzers = []
				@@jpg     = nil
				@@pdf     = nil
				@@count   = 0
				@@index   = 0
				
				@@testcases_since_update = 0
				@@last_update            = ::Time.now

				def self.add_fuzzer( name, data )
					@@fuzzers << [ name, data ]
				end
				
				def self.jpg( data )
					@@jpg = data
				end
				
				def self.pdf( data )
					@@pdf = data
				end
				
				def do_GET( request, response )
					if( request.path == '/current_fuzzer' )
						response.status          = 200
						response['Content-Type'] = 'text/html'
						response.body            = ''
						response['fuzzer']       = @@fuzzers[ @@index ][ 0 ]
					elsif( request.path == '/grind.jpg' )
						response.status          = 200
						response['Content-Type'] = 'image/jpeg'
						response.body            = @@jpg
					elsif( request.path == '/grind.pdf' )
						response.status          = 200
						response['Content-Type'] = 'application/pdf'
						response.body            = @@pdf
					elsif( request.path == '/grind.js' )
						response.status          = 200
						response['Content-Type'] = 'text/javascript'
						response.body            = 'var ph33r;'
					elsif( request.path == '/grind.html' )
						response.status          = 200
						response['Content-Type'] = 'text/html'
						response.body            = '<p>Hello from grind.html</p>'
					elsif( request.path == '/grind.svg' )
						response.status          = 200
						response['Content-Type'] = 'image/svg+xml'
						response.body            = "<?xml version='1.0' standalone='no'?><!DOCTYPE svg PUBLIC '-//W3C//DTD SVG 1.1//EN' 'http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd'><svg xmlns='http://www.w3.org/2000/svg' version='1.1'><circle cx='50' cy='50' r='50' fill-opacity='.3' fill='orange'/><circle cx='100' cy='50' r='50' fill-opacity='.3' fill='orange'/><circle cx='75' cy='100' r='50' fill-opacity='.3' fill='orange'/><text x='40' y='70' fill='black'>Grinder</text></svg>"
					elsif( request.path == '/grinder' )
						
						@@testcases_since_update += 1

						minutes_since_last_update = ( ( ::Time.now - @@last_update ) / 60 ).round
						
						if( minutes_since_last_update > $webstats_update_minutes )
							begin
								if( $webstats_baseurl and $webstats_key )
									web = ::Grinder::Core::WebStats.new( $grinder_node, $webstats_baseurl, $webstats_key, $webstats_username, $webstats_password )
									
									web.update_node_fuzz_status( @@testcases_since_update / $webstats_update_minutes )
									
									@@last_update = ::Time.now
									
									@@testcases_since_update = 0
									
									web = nil
								end
							rescue
							end
						end

					
						@@count += 1
						if( @@count > $swap_fuzzer_count )
							@@count = 0
							@@index += 1
							if( @@index > ( @@fuzzers.length - 1 ) )
								@@index = 0
							end
						end
						
						response.status          = 200
						response['Content-Type'] = 'text/html'
						response.body            = @@fuzzers[ @@index ][ 1 ]
					else
						# all requests that would generate a 404 response are instead handled with a 301 redirect back to /grinder
						response.status          = 301
						response['Content-Type'] = 'text/html'
						response['Location']     = '/grinder'
						response.body            = ''
					end
				end
			end
			
			def initialize( address, port )
				@address         = address
				@port            = port
				@dummy_websocket = nil
				@server          = nil
				@thread          = nil
				
				if( $webstats_baseurl and $webstats_key )
					web = ::Grinder::Core::WebStats.new( $grinder_node, $webstats_baseurl, $webstats_key, $webstats_username, $webstats_password )
					web.update_node_fuzz_status( 0 )
					web = nil
				end
				
				::Dir.foreach( $fuzzers_dir ) do | file |				
					ext = ::File.extname( file )
					if( ext.downcase == '.html' )
						name = file[0,file.length-ext.length]
						::File.open( "#{$fuzzers_dir}#{file}", 'r' ) do | f |
							print_status( "Adding fuzzer '#{name}' to the Grinder server" )
							GrinderServlet.add_fuzzer( name, f.read( f.stat.size ) )
						end
					end
				end

				::File.open( './data/grind.jpg', 'rb' ) do | f |
					GrinderServlet.jpg( f.read( f.stat.size ) )
				end
				
				::File.open( './data/grind.pdf', 'rb' ) do | f |
					GrinderServlet.pdf( f.read( f.stat.size ) )
				end
				
			end
			
			def start
				return if @thread and @thread.alive?
				print_status( "Grinder server running on #{@address}:#{@port}" )
				@thread = ::Thread.new do
					# try to create a socket for a dummy websocket server, ignore if this fails
					begin
						@dummy_websocket = ::TCPServer.open( @address, 6666 )
					rescue
						@dummy_websocket = nil
					end
					
					@server = ::WEBrick::HTTPServer.new(
							:BindAddress  => @address,
							:Port         => @port,
							:AccessLog    => [],
							:Logger       => NoLog.new
						)
					
					@server.mount( '/', GrinderServlet )

					@server.start
				end
			end

			def wait
				@thread.join
			end
			
			def stop
				print_status( "Stopping the webserver" )
				@thread.kill
				@thread = nil
				if( @server )
					@server.stop()
					@server = nil
				end
				if( @dummy_websocket )
					@dummy_websocket.close()
					@dummy_websocket = nil
				end
			end
		end

	end

end

if( $0 == __FILE__ )

	print_init( 'SERVER', false )
	
	print_status( "Starting at #{::Time.new.strftime( "%Y-%m-%d %H:%M:%S" )}" )
			
	ARGV.each do | arg |
		if( arg.include?( '--config=' ) )
			config_file = arg[9,arg.length]
			begin
				require config_file
			rescue ::LoadError
				print_error( "Failed to load the config file '#{config_file}'." )
				::Kernel::exit( false )
			end
		end
	end
	
	server = Grinder::Core::Server.new( $server_address, $server_port )
	
	server.start
	
	server.wait
	
	print_status( "Finished at #{::Time.new.strftime( "%Y-%m-%d %H:%M:%S" )}" )

	::Kernel::exit( true )
end