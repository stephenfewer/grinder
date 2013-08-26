#
# Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
# Licensed under a 3 clause BSD license (Please see LICENSE.txt)
# Source code located at https://github.com/stephenfewer/grinder
#

$:.unshift( '.' )

require 'core/configuration'
require 'core/logging'
require 'digest/sha2'

class Grinder
	
	BROWSER_CLASS_IE = '.\browser\internetexplorer.rb'
	BROWSER_CLASS_CM = '.\browser\chrome.rb'
	BROWSER_CLASS_FF = '.\browser\firefox.rb'
	BROWSER_CLASS_SF = '.\browser\safari.rb'
	#BROWSER_CLASS_OP = '.\browser\opera.rb'

	def initialize( arguments )
		@browser_type  = nil
		@browser_class = nil
		@config_file   = 'config'
		@fuzzer        = nil
		@verbose       = true
		
		use_browser = lambda do | browser |
			browser = browser.upcase
			if( browser == 'IE' or browser == 'INTERNETEXPLORER' )
				@browser_type  = 'IE'
				@browser_class = BROWSER_CLASS_IE
			elsif( browser == 'CM' or browser == 'CHROME' )
				@browser_type  = 'CM'
				@browser_class = BROWSER_CLASS_CM
			elsif( browser == 'FF' or browser == 'FIREFOX' )
				@browser_type  = 'FF'
				@browser_class = BROWSER_CLASS_FF
			elsif( browser == 'SF' or browser == 'SAFARI' )
				@browser_type  = 'SF'
				@browser_class = BROWSER_CLASS_SF
			#elsif( browser == 'OP' or browser == 'OPERA' )
			#	@browser_type  = 'OP'
			#	@browser_class = BROWSER_CLASS_OP
			end
		end
		
		arguments.each do | arg |
			if( arg.include?( '--quiet' ) )
				@verbose = false
			elsif( arg.include?( '--config=' ) )
				@config_file = arg[9,arg.length]
			elsif( arg.include?( '--fuzzer=' ) )
				@fuzzer = arg[9,arg.length]
			elsif( arg.include?( '--browser=' ) )
				use_browser.call( arg[10,arg.length] )
			else
				use_browser.call( arg )
			end
		end
		
	end
	
	def systest
	
		if( not config_test() )
			return false
		end
		
		# this is kinda hacky but it should prevent people from trying to run the node incorectly.
		if( not ::File.exist?( ".\\grinder.rb" ) )
			print_error( "Error, you are not running this node from the \\grinder\\node\\ directory. You need to change the working directory (cd path\\to\\grinder\\node\\) and try again." )
			return false
		end

		check_dll = lambda do | dllname, dlltitle |
			
			root = "c:\\windows"
			if( ENV.include?( 'SystemRoot' ) )
				root = ENV[ 'SystemRoot' ]
			end
			
			sysdir = 'system32'
			if( ::Dir.exist?( "#{root}\\syswow64\\" ) )
				sysdir = 'syswow64'
			end
			
			dllpath = "#{root}\\#{sysdir}\\#{dllname}"
			
			if( not ::File.exist?( dllpath ) )
				begin
					::File.open( ".\\data\\#{dllname}", 'rb' ) do | dll_src |
						::File.open( dllpath, 'wb' ) do | dll_dst |
							dll_dst.write( dll_src.read( dll_src.stat.size ) )
							print_status( "Created the grinder #{dlltitle} DLL '#{dllpath}'." )
						end
					end
				rescue
					print_error( "Error, the grinder #{dlltitle} DLL '#{dllpath}' does not exist. Please manually copy this file from the \\grinder\\node\\data\\ directory." )
					return false
				end
			end
			
			::File.open( ".\\data\\#{dllname}", 'rb' ) do | dll_src |
				::File.open( dllpath, 'rb' ) do | dll_dst |
					
					gl1 = dll_src.read( dll_src.stat.size )
					
					gl2 = dll_dst.read( dll_dst.stat.size )

					if( ::Digest::SHA256.digest( gl1 ) != ::Digest::SHA256.digest( gl2 ) )
						print_warning( "Warning, the grinder #{dlltitle} DLL '#{dllpath}' does not match the one from the \\grinder\\node\\data\\ directory. Please make sure you are using the latest one." )
					end
				end
			end
			
			return true
		end
		
		if( not check_dll.call( 'grinder_logger.dll', 'logger' ) )
			return false
		end

		# sf: we are not using heaphook yet so this stays commented out for now.
		#if( not check_dll.call( 'grinder_heaphook.dll', 'heap hook' ) )
		#	return false
		#end
		
		return true
	end

	def run
	
		if( not config_init( @config_file ) )
			print_error( "Failed to load the config file '#{@config_file}'." )
			return false
		end
		
		print_status( "Using the config file '#{@config_file}'..." )
		
		if( not systest() )
			print_error( "System test failed! Please ensure this Grinder node is installed correctly." )
			return false
		end

		if( not @browser_type or not @browser_class )
			print_error( "No suitable browser was specified, unable to continue." )
			return false
		end
		
		print_status( "Bringing up Grinder node '#{$grinder_node}'..." )
		
		continue_pid = ::Process.spawn( ".\\data\\continue.exe" )
		print_status( "Started the Grinder continue process #{continue_pid}" )
		
		server_reset  = 0
		$server_pid   = nil
		$debugger_pid = nil
		
		while( true )
		
			kill_thread  = nil

			if( not $server_pid )
				$server_pid = ::Process.spawn( "ruby -I. .\\core\\server.rb --config=#{@config_file} --browser=#{@browser_type} #{ ( @fuzzer ? '--fuzzer='+@fuzzer : '' ) } #{ ( not @verbose ? '--quiet' : '' ) }" )
				sleep( 2 )
				print_status( "Started the Grinder server process #{$server_pid}" )
				server_reset = 12
			end
			
			$debugger_pid = ::Process.spawn( "ruby -I. #{@browser_class} --config=#{@config_file} --path=/grinder #{ ( not @verbose ? '--quiet' : '' ) }" )
			print_status( "Started the Grinder debugger process #{$debugger_pid}" )
			
			if( $debugger_pid and $debugger_restart_minutes )
				# start a thread to wait N minutes before killing the debugger process. We do this so we start
				# afresh exery N minutes. This help avoid running a target browser for hours without generating
				# a crash and a browser memory leak gobbeling up a grinder nodes memory (or the browser being
				# deadlocked for some reason).
				kill_thread = ::Thread.new do
					
					sleep( $debugger_restart_minutes * 60 )
					
					print_status( "Killing the debugger process #{$debugger_pid} after #{$debugger_restart_minutes} minutes." )

					begin
						::Process.kill( "KILL", $debugger_pid )
					rescue ::Errno::ESRCH, Errno::ECHILD
					end
					
					if( server_reset <= 0 )
						# every X times kill/restart the web server as their seems to be a memory leak (Due to event handles on Windows 2008)...
						print_status( "Killing the server process #{$server_pid}." )

						begin
							::Process.kill( "KILL", $server_pid )
							::Process.wait( $server_pid )
						rescue ::Errno::ESRCH, Errno::ECHILD
						end
						
						$server_pid = nil
					else
						server_reset -= 1
					end
				end
			end
			
			# block for the debugger to either exit due to a crash or to be killed by the above kill_thread
			begin
				::Process.wait( $debugger_pid )
			rescue ::Errno::ESRCH, Errno::ECHILD, Errno::EINVAL
			end
			
			$debugger_pid = nil
			
			# if the kill_thread is still alive by here we kill it
			if( kill_thread and kill_thread.alive? )
				kill_thread.kill
			end
		end
		
		return true
	end

end

if( $0 == __FILE__ )
	
	verbose = true
	
	if( ARGV.include?( '--help' ) or ARGV.include?( '-h' ) or ARGV.include?( '/h' ) or ARGV.include?( '/help' ) )
		print_simple( "Usage: >ruby.exe grinder.rb [options] [browser]" )
		print_simple( "  --config=ConfigFile.rb     Specify an alternative config file to use for this node." )
		print_simple( "  --fuzzer=FuzzerToUse       Specify a single fuzzer to use with this node." )
		print_simple( "  --browser=BrowserToFuzz    Specify the browser to fuzz (e.g. IE, CM, FF, SF)" )
		print_simple( "  --quiet                    Don't print any status/error messages to stdout" )
		::Kernel.exit( true )
	elsif( ARGV.include?( '--version' ) or ARGV.include?( '-v' ) or ARGV.include?( '/v' ) or ARGV.include?( '/version' ) )
		print_simple( "Version #{$version_major}.#{$version_minor}#{$version_dev ? '-Dev' : '' }" )
		::Kernel.exit( true )
	elsif( ARGV.include?( '--quiet' ) or ARGV.include?( '-q' ) or ARGV.include?( '/q' ) or ARGV.include?( '/quiet' ) )
		verbose = false
	end

	print_init( 'GRINDER', verbose )

	print_status( "Starting at #{::Time.new.strftime( "%Y-%m-%d %H:%M:%S" )}" )
	
	grinder = Grinder.new( ARGV )
	
	success = grinder.run
	
	print_status( "Finished at #{::Time.new.strftime( "%Y-%m-%d %H:%M:%S" )}" )

	::Kernel::exit( success )
end
