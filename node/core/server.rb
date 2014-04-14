#
# Copyright (c) 2014, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
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
			
			class GrinderServlet < ::WEBrick::HTTPServlet::AbstractServlet

				@@fuzzers    = []
				@@logging_js = nil
				@@jpg        = nil
				@@pdf        = nil
				@@count      = 0
				@@index      = 0
				@@reductor   = nil
				
				@@testcases_since_update = 0
				@@last_update            = ::Time.now
				
				def self.reduction( r )
					# 'The Reductor Curse is a spell used to blast solid objects into pieces' - http://harrypotter.wikia.com/wiki/Reductor_Curse
					@@reductor = r
				end
				
				def self.add_fuzzer( name, data )
					@@fuzzers << [ name, data ]
				end
				
				def self.logging_js( data )
					@@logging_js = data
				end
				
				def self.jpg( data )
					@@jpg = data
				end
				
				def self.pdf( data )
					@@pdf = data
				end

				def tcpm_update
					@@testcases_since_update += 1
					
					minutes_since_last_update = ( ( ::Time.now - @@last_update ) / 60 ).round
					
					# currently we hardcode this to 5 minutes as the window for activity in system.php is also 5 minutes.
					webstats_update_minutes   = 5
					
					if( minutes_since_last_update > webstats_update_minutes )
						begin
							if( $webstats_baseurl and $webstats_key )
								web = ::Grinder::Core::WebStats.new( $grinder_node, $webstats_baseurl, $webstats_key, $webstats_username, $webstats_password, $webstats_https )
								
								if( @@reductor )
									web.update_job_status( @@testcases_since_update / webstats_update_minutes, ::Grinder::Core::WebStats::JOB_REDUCTION )
								else
									web.update_job_status( @@testcases_since_update / webstats_update_minutes, ::Grinder::Core::WebStats::JOB_FUZZING )
								end
								
								@@last_update = ::Time.now
									
								@@testcases_since_update = 0
							end
						rescue
						end
					end
					
					@@count += 1
					if( @@fuzzers.length > 1 and @@count > $swap_fuzzer_count )
						@@count = 0
						@@index += 1
						if( @@index > ( @@fuzzers.length - 1 ) )
							@@index = 0
						end
					end
				end
				
				def do_POST( request, response )
					if( request.path == '/testcase_crash' )
						success                  = @@reductor ? @@reductor.testcase_crash( request.query['hash'] ) : false
						response.status          = success ? 200 : 404
						response['Content-Type'] = 'text/html'
						response.body            = ''
					elsif( request.path == '/duplicate_crash' )
						success                  = @@reductor ? @@reductor.duplicate_crash( request.query['hash'] ) : false
						response.status          = 200
						response['Content-Type'] = 'text/html'
						response['duplicate']    = success.to_s
						response.body            = ''
					#elsif( request.path == '/previous_crash' )
					#	result                   = @@reductor ? @@reductor.previous_crash( request.query['hash'] ) : nil
					#	response.status          = 200
					#	response['Content-Type'] = 'text/html'
					#	response['hash']         = result ? result : ''
					#	response.body            = ''
					elsif( request.path == '/current_fuzzer' )
						response.status          = @@fuzzers.length > @@index ? 200 : 404
						response['Content-Type'] = 'text/html'
						response.body            = ''
						response['fuzzer']       = @@fuzzers.length > @@index ? @@fuzzers[ @@index ][ 0 ] : ''
					else
						response.status          = 404
						response['Content-Type'] = 'text/html'
						response.body            = ''
					end
				end
				
				def do_GET( request, response )
					if( request.path == '/grinder' )
						tcpm_update
						response.status          = @@fuzzers.length > @@index ? 200 : 404
						response['Content-Type'] = 'text/html; charset=utf-8;'
						response.body            = @@fuzzers.length > @@index ? @@fuzzers[ @@index ][ 1 ] : ''
					elsif( request.path == '/favicon.ico' )
						response.status          = 404
						response['Content-Type'] = 'text/html'
						response.body            = ''
					elsif( request.path == '/logging.js' )
						response.status          = 200
						response['Content-Type'] = 'text/javascript'
						response.body            = @@logging_js
					elsif( request.path == '/testcase_generate' )
						html                     = @@reductor ? @@reductor.testcase_generate : nil
						response['Content-Type'] = 'text/html; charset=utf-8;'
						if( html )
							tcpm_update
							response.status      = 200
							response.body        = html
						else
							response.status      = 404
							response.body        = ''
						end
					elsif( request.path == '/testcase_processed' )
						@@reductor.testcase_processed if @@reductor
						# use a 307 temporary redirect back to /testcase_generate to keep this show on the road
						response.status          = 307 
						response['Content-Type'] = 'text/html; charset=utf-8;'
						response['Location']     = '/testcase_generate'
						response.body            = ''
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
						response['Content-Type'] = 'text/html; charset=utf-8;'
						response.body            = '<p>Hello from grind.html</p>'
					elsif( request.path == '/grind.css' )
						response.status          = 200
						response['Content-Type'] = 'text/css'
						response.body            = 'body { color:red; }'
					elsif( request.path == '/grind.swf' )
						response.status          = 200
						response['Content-Type'] = 'application/x-shockwave-flash'
						response.body            = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
					elsif( request.path == '/grind.svg' )
						response.status          = 200
						response['Content-Type'] = 'image/svg+xml'
						response.body            = "<?xml version='1.0' standalone='no'?><!DOCTYPE svg PUBLIC '-//W3C//DTD SVG 1.1//EN' 'http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd'><svg xmlns='http://www.w3.org/2000/svg' version='1.1'><circle cx='50' cy='50' r='50' fill-opacity='.3' fill='orange'/><circle cx='100' cy='50' r='50' fill-opacity='.3' fill='orange'/><circle cx='75' cy='100' r='50' fill-opacity='.3' fill='orange'/><text x='40' y='70' fill='black'>Grinder</text></svg>"
					else
						# all requests that would generate a 404 response are instead handled with a 307 temporary redirect back to /grinder
						response.status          = 307
						response['Content-Type'] = 'text/html; charset=utf-8;'
						response['Location']     = '/grinder'
						response.body            = ''
					end
				end
			end
			
			def initialize( address, port, browser=nil, fuzzer=nil, reduction=nil )
				@address         = address
				@port            = port
				@browser         = browser
				@dummy_websocket = nil
				@server          = nil
				@thread          = nil
				
				GrinderServlet.reduction( reduction )
				
				if( $webstats_baseurl and $webstats_key )
					web = ::Grinder::Core::WebStats.new( $grinder_node, $webstats_baseurl, $webstats_key, $webstats_username, $webstats_password, $webstats_https )
					if( reduction )
						web.update_job_status( 0, ::Grinder::Core::WebStats::JOB_REDUCTION )
					else
						web.update_job_status( 0, ::Grinder::Core::WebStats::JOB_FUZZING )
					end
				end
				
				# if no reduction object is specified we treat this server instance as a server for reduction/verification 
				# and not fuzzing thus we dont send an initial status update or load any of the fuzzers.
				if( not reduction )
					$fuzzers_dir = $fuzzers_dir + ( $fuzzers_dir.end_with?( "\\" ) ? '' : "\\" )

					fuzzer_directories = [ $fuzzers_dir ]
					
					if( @browser )
						fuzzer_directories << $fuzzers_dir + @browser + "\\"
					end
					
					fuzzer_directories.each do | fuzzdir |
					
						next if not ::Dir.exist?( fuzzdir )
						
						::Dir.foreach( fuzzdir ) do | fuzzfile |
						
							ext = ::File.extname( fuzzfile )
							
							if( ext.downcase == '.html' )
							
								name = fuzzfile[ 0, fuzzfile.length - ext.length ]
								
								# if the user has specified a fuzzer on the command line (via --fuzzer=MyAwesomeFuzzer1) we 
								# can choose to only load the specified fuzzer and no others.
								if( fuzzer and fuzzer != name )
									next
								end
								
								::File.open( "#{fuzzdir}#{fuzzfile}", 'r' ) do | f |
									print_status( "Adding fuzzer '#{name}' to the testcase server" )
									GrinderServlet.add_fuzzer( name, f.read( f.stat.size ) )
								end
							end
							
						end
						
					end
				end
				
				::File.open( './data/logging.js', 'r' ) do | f |
					GrinderServlet.logging_js( f.read( f.stat.size ) )
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
				print_status( "Testcase server running on #{@address}:#{@port}" )
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
				print_status( "Stopping the testcase server" )
				if( @thread )
					@thread.kill
					@thread = nil
				end
				if( @server )
					@server.shutdown
					@server.stop
					@server = nil
				end
				if( @dummy_websocket )
					@dummy_websocket.close
					@dummy_websocket = nil
				end
			end
		end

	end

end

if( $0 == __FILE__ )

	verbose = true
	
	if( ARGV.include?( '--quiet' ) or ARGV.include?( '-q' ) or ARGV.include?( '/q' ) or ARGV.include?( '/quiet' ) )
		verbose = false
	end
	
	print_init( 'SERVER', verbose, false )
	
	print_status( "Starting at #{::Time.new.strftime( "%Y-%m-%d %H:%M:%S" )}" )
	
	browser = nil
	fuzzer  = nil
	
	ARGV.each do | arg |
		if( arg.include?( '--browser=' ) )
			browser = arg[10,arg.length]
		elsif( arg.include?( '--fuzzer=' ) )
			fuzzer = arg[9,arg.length]
		elsif( arg.include?( '--config=' ) )
			config_file = arg[9,arg.length]
			begin
				require config_file
			rescue ::LoadError
				print_error( "Failed to load the config file '#{config_file}'." )
				::Kernel::exit( false )
			end
		end
	end
	
	server = Grinder::Core::Server.new( $server_address, $server_port, browser, fuzzer )
	
	server.start
	
	server.wait
	
	print_status( "Finished at #{::Time.new.strftime( "%Y-%m-%d %H:%M:%S" )}" )

	::Kernel::exit( true )
end