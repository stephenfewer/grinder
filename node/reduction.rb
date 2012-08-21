#
# Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
# Licensed under a 3 clause BSD license (Please see LICENSE.txt)
# Source code located at https://github.com/stephenfewer/grinder
#

$:.unshift( '.' )

require 'core/configuration'
require 'core/logging'
require 'core/server'
require 'core/xmlcrashlog'
require 'core/crypt'
require 'lib/metasm/metasm'

class Reduction

	BROWSER_CLASS_IE = '.\browser\internetexplorer.rb'
	BROWSER_CLASS_CM = '.\browser\chrome.rb'
	BROWSER_CLASS_FF = '.\browser\firefox.rb'
	BROWSER_CLASS_SF = '.\browser\safari.rb'
	#BROWSER_CLASS_OP = '.\browser\opera.rb'
	
	class SkipAndKeepItems
		
		attr_reader :keeping, :skipping
		
		def initialize( items )
			@keeping  = items
			@skipping = ::Array.new
			@first    = nil
		end
		
		def finished?
			return ( @keeping.empty? or ( @first and ( @first == @keeping.first or @first == @skipping.last ) ) ) ? true : false
		end
		
		def skip
			@first = @keeping[0] if @keeping.length == 1
			item = @keeping.pop
			@skipping.push( item )
			return item
		end
		
		def keep
			@first = @keeping.first if not @first
			item = @skipping.pop
			@keeping.unshift( item )
			return item
		end
	end
	
	def initialize( arguments )
		@config_file      = 'config'
		@browser_type     = nil
		@browser_exe      = nil
		@browser_class    = nil
		@xmlcrashlog      = nil
		@log_file         = nil
		@save_file        = nil
		@debugger_pid     = nil
		@reduction_server = nil
		@verify           = false
		@reduce           = false
		@verbose          = true
		@crash_hashes     = ::Hash.new
		@opts             = ::Hash.new
		@idxs             = nil
		@elems            = nil
		@genopts          = nil
		@hash             = nil
		@key              = nil
		@keypass          = nil
		
		arguments.each do | arg |
			if( arg.include?( '--quiet' ) or  arg.include?( '/quiet' ) or  arg.include?( '/q' ) or  arg.include?( '-q' ) )
				@verbose = false
			elsif( arg.include?( '--config=' ) )
				@config_file = arg[9,arg.length]
			elsif( arg.include?( '--key=' ) )
				@key = arg[6,arg.length]
			elsif( arg.include?( '--keypass=' ) )
				@keypass = arg[10,arg.length]
			elsif( arg.include?( '--hash=' ) )
				@hash = arg[7,arg.length].upcase
			elsif( arg.include?( '--verify' ) )
				@verify = true
			elsif( arg.include?( '--reduce' ) )
				@reduce = true
			elsif( arg.include?( '--browser=' ) )
				browser = arg[10,arg.length].upcase
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
			elsif( arg.include?( '--log=' ) )
				@log_file = arg[6,arg.length]
			elsif( arg.include?( '--save=' ) )
				@save_file = arg[7,arg.length]
			end
		end
		
	end

	def systest
	
		if( not config_test() )
			return false
		end
		
		# this is kinda hacky but it should prevent people from trying to run the node incorectly.
		if( not ::File.exist?( ".\\reduction.rb" ) )
			print_error( "Error, you are not running this node from the \\grinder\\node\\ directory. You need to change the working directory (cd path\\to\\grinder\\node\\) and try again." )
			return false
		end
		
		if( not @verify and not @reduce )
			print_error( "What do you want to do? Use either the --verify or --reduce params." )
			return false
		end
		
		if( @verify and @reduce )
			print_error( "What do you want to do? Use either the --verify or --reduce params (but not both)." )
			return false
		end
		
		if( not @save_file )
			print_warning( "No save file has been specified. Any verified or reduced testcase will not be saved. Use the --save=FILE param." )
		end
		
		if( not @browser_type or not @browser_class )
			print_error( "A valid browser has not been specified. Use the --browser=BROWSER param." )
			return false
		end
		
		if( not @log_file )
			print_error( "A valid log file has not been specified. Use the --log=FILE param." )
			return false
		end
		
		if( not @hash or @hash.length != 17 )
			print_error( "The origional crash hash has not been specified. Use the --hash=XXXXXXXX.XXXXXXXX param." )
			return false
		end
		
		if( not ::File.exist?( @log_file ) )
			print_error( "Failed to open the log file '#{@log_file}'." )
			return false
		end
		
		if( Grinder::Core::Crypt.encrypted?( @log_file ) and not @key )
			print_error( "Error, The log file '#{@log_file}' appears to be encrypted. Use the --key=PRIVATEKEY.PEM [--keypass=PASSPHRASE] params, or else manually decrypt the log file first." )
			return false
		end
		
		return true
	end

	def spawn_browser
		kill_browser
		@debugger_pid = ::Process.spawn( "ruby -I. #{@browser_class} --reduction --quiet --path=/testcase_generate --config=#{@config_file}" )
	end
	
	def kill_browser
		if( @debugger_pid )
			begin
				::Process.kill( "KILL", @debugger_pid )
				::Process.wait( @debugger_pid )
				# we might need to wait for continue.exe to close any crash dialogs...
				loop do
					found = false
					Metasm::WinOS.list_processes.each do | proc |
						mods = proc.modules
						if( mods )
							if( mods.first and mods.first.path.include?( @browser_exe ) )
								sleep( 0.25 )
								found = true
							end
						end
					end
					break if not found
				end
			rescue ::Errno::ESRCH
			end
			@debugger_pid = nil
		end
	end
	
	def duplicate_crash( hash )
		if( hash == @hash )
			return true
		end
		return @crash_hashes.has_key?( hash )
	end
	
	#def previous_crash( hash )
	#	if( @crash_hashes.index( hash ) > 0 )
	#		return @crash_hashes[ @crash_hashes.index( hash ) - 1 ]
	#	end
	#	return nil
	#end

	def testcase_crash( hash )
	
		thread = ::Thread.new do
		
			finished_pass = false
			
			# if this is a new crash for this reduction, log the hash
			if( @crash_hashes.has_key?( hash ) )
				@crash_hashes[hash] += 1
			else
				@crash_hashes[hash]  = 1
			end
			
			# flag the current testcase as being able to trigger a crash (moving on to the next pass if required)...
			case @current_pass
				when 1
					# Initial verification
					finished_pass = true
				when 2
					# Reducing elements
					spawn_browser
				when 3
					# Reducing idx's
					spawn_browser
				when 4
					# Final verification
					finished_pass = true
				else
					finished_pass = true
			end
			
			if( finished_pass )
				@reduction_server.stop
				::Thread.current.kill
			end
		end
		
		thread.join
		
		return true
	end

	# generate the next testcase to try
	def testcase_generate
	
		html = ''
		
		thread = ::Thread.new do
		
			finished_pass = false

			case @current_pass
				when 1
					# Initial verification
					finished_pass = @genopts.finished?
					@genopts.skip().call if not finished_pass
				when 2
					# Reducing elements
					finished_pass = @elems.finished?
					@elems.skip if not finished_pass
				when 3
					# Reducing idx's
					finished_pass = @idxs.finished?
					@idxs.skip if not finished_pass
				when 4
					# Final verification
					# do nothing, we just want to verify the final testcase will still generate a crash
				else
					finished_pass = true
			end
			
			if( finished_pass )
				@reduction_server.stop
				::Thread.current.kill
			end
			
			# generate the html testcase from the log file
			html = @xmlcrashlog.generate_html( @opts, @elems ? @elems.skipping : [], @idxs ? @idxs.skipping : [] )
		end
		
		thread.join
		
		# and serve it back out to the browser via the server
		return html
	end
	
	# return true if we are to continue generating and serving out testcases, or false if its time to finish.
	def testcase_processed
	
		continue = true

		thread = ::Thread.new do
		
			kill_browser

			case @current_pass
				when 1
					# Initial verification
					@genopts.keep
				when 2
					# Reducing elements
					@elems.keep
				when 3
					# Reducing idx's
					@idxs.keep
				when 4
					# Final verification
					# booo, pass 4 has failed!?!.
					continue = false
				else
					continue = false
			end

			# while we still have testcases to generate...
			if( continue )
				# we go again an try the next testcase in a new browser instance
				spawn_browser
			else
				@reduction_server.stop
				::Thread.current.kill
			end
		end
		
		thread.join
		
		return continue
	end
	
	# pass 1: initial verification (find out if we can cause a crash, do we need to enable code comments, do we need to tickle?)
	# pass 2: skip elements (find what elements we can skip to still cause a crash)
	# pass 3: skip idxs (find out what idxs we can remove to still generate a crash)
	# pass 4: final verification (finally verify the end result still generates a crash)
	def reduction( pass )
		
		return false if pass > 4
		
		@current_pass = pass
		
		case @current_pass
			when 1

				p = [
					::Proc.new do
						@opts['print_message_comments']  = false

						@opts['uncomment_code_comments'] = @opts['print_code_comments'] = false
					end,
					::Proc.new do
						@opts['uncomment_code_comments'] = @opts['print_code_comments'] = true
					end,
					::Proc.new do
						@opts['uncomment_code_comments'] = @opts['print_code_comments'] = false
						
						line = ''
						@xmlcrashlog.generate_elems( @opts ).each do | elem |
							line << "try { tickle( #{elem} ); } catch(e){}\n" # some of these elems might not exist later on (due to @skip_elems) but we wont know yet (hence try/catch).
						end
						
						@opts['testcase_append_function'] = line << @opts['testcase_append_function']						
					end,
					::Proc.new do
						@opts['uncomment_code_comments'] = @opts['print_code_comments'] = true
						
						# XXX: @opts['testcase_append_function'] will already include the element tickle stuff from above.
						
						#line = ''
						#@xmlcrashlog.generate_elems( @opts ).each do | elem |
						#	line << "tickle( #{elem} );\n"
						#end
						#@opts['testcase_append_function'] = line << @opts['testcase_append_function']
					end
				]
				
				p.reverse!
				
				@genopts = SkipAndKeepItems.new( p )
				
				print_status( "Performing pass 1: Initial verification." )
			when 2
				
				@elems = SkipAndKeepItems.new( @xmlcrashlog.generate_elems( @opts ) )

				print_status( "Performing pass 2: Reducing elements (#{@elems.keeping.length} elements's)." )
			when 3

				@idxs = SkipAndKeepItems.new( @xmlcrashlog.generate_idxs( @opts, @elems.skipping ) )

				print_status( "Performing pass 3: Reducing idx's (#{@idxs.keeping.length} idx's)." )
			when 4
				print_status( "Performing pass 4: Final verification." )
		end

		# spin up a server to serve out the html testcase
		@reduction_server = Grinder::Core::Server.new( $server_address, $server_port, @browser_type, nil, self )
		
		@reduction_server.start

		# start a broswer instance to visit /testcase_generate
		spawn_browser

		@reduction_server.wait
		
		kill_browser
		
		success = true
		
		# print pass results (like above)
		case @current_pass
			when 1
				success = ( not @crash_hashes.empty? )
				if( success )
					print_status( "Finished pass 1: Successfully performed the initial verification." )
				else
					print_error( "Finished pass 1: Couldn't trigger a crash." )
				end
			when 2
				print_status( "Finished pass 2: Reduced elements to #{@elems.keeping.length}." )
			when 3
				print_status( "Finished pass 3: Reduced idx's to #{@idxs.keeping.length}." )
			when 4
				print_status( "Finished pass 4: Final verification." )
		end
		
		return success
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

		exe = { 
			'IE' => $internetexplorer_exe,
			'CM' => $chrome_exe,
			'FF' => $firefox_exe,
			'SF' => $safari_exe,
			'OP' => $opera_exe
		}[@browser_type]
		
		@browser_exe = exe[ exe.rindex('\\') + 1, exe.length - exe.rindex('\\') ]

		# these fixups try to ensure any testcase line which tries to reload the page (typically 
		# the end of the testcase, in order to get a new testcase during fuzzing) will infact
		# signal the end of the current testcase to the reduction server.
		fixups = {
			"+ window.location.host + '/grinder';" => "+ window.location.host + '/testcase_processed';",
			"+ location.host + '/grinder';"        => "+ location.host + '/testcase_processed';",
			"location.reload();"                   => "window.location.href = window.location.protocol + '//' + window.location.host + '/testcase_processed';",
			"window.location.reload();"            => "window.location.href = window.location.protocol + '//' + window.location.host + '/testcase_processed';",
			"/grinder"                             => "/testcase_processed"
		}

		# get this nodes testcase generation options
		@opts = @opts.merge( $testcase_opts )
		
		# force lines to be wrapped in try/catch to avoid any js exceptions killing a testcase (which would interph33r with automation)
		@opts['try_catch'] = true
		
		# in case a 'testcase_fixups' hash isnt set, we set one
		@opts['testcase_fixups'] = ::Hash.new if not @opts.has_key?( 'testcase_fixups' )
		
		# and the same for the 'testcase_append_function' string 
		@opts['testcase_append_function'] = '' if not @opts.has_key?( 'testcase_append_function' )
		
		# now merge in our window.location fixups over the users ones
		@opts['testcase_fixups'] = @opts['testcase_fixups'].merge( fixups )
		
		# merge in a final line for the testcase() function to visit the reduction servers /testcase_processed. This might end up being a duplicate final line but we must ensure it esists either way.
		@opts['testcase_append_function'] << ";\nwindow.location.href = window.location.protocol + '//' + window.location.host + '/testcase_processed';\n"
		
		# parse the log file so we can generate testcases from it
		@xmlcrashlog = XmlCrashLog.new( @log_file, @key, @keypass )
			
		if( not @xmlcrashlog.parse )
			print_error( "Error, Failed to parse the xml crash log file '#{@log_file}'." )
			return false
		end
		
		continue_pid = ::Process.spawn( ".\\data\\continue.exe" )
		
		print_status( "Started the Grinder continue process #{continue_pid}" )
		
		success = false
		
		if( @verify )
			
			print_status( "Beginning the verification of '#{@log_file}' against '#{@browser_type}'..." )
			
			reduction( 1 )

			success = ( not @crash_hashes.empty? )
			
			if( success and @crash_hashes.first[0] == @hash )
				print_status( "Success, verified the testcase (Automatically generates the origional crash '#{@crash_hashes.first[0]}')." )
			elsif( success and @crash_hashes.first[0] != @hash )
				print_status( "Success, verified the testcase (Automatically generates a different crash '#{@crash_hashes.first[0]}')." )
			else
				print_error( "Error, failed to verify the testcase (Couldn't trigger the origional crash)." )
			end
			
		elsif( @reduce )
			
			print_status( "Beginning the reduction of '#{@log_file}' against '#{@browser_type}'..." )
			
			1.upto( 4 ) do | pass |
				break if not reduction( pass )
			end
			
			success = ( not @crash_hashes.empty? )
			
			if( success ) # XXX: test if the new log is smaller
				print_status( "Success, reduced the testcase (Saw #{@crash_hashes.length} unique crash#{@crash_hashes.length > 1 ? 'es' : '' } in the process)." )
				# XXX: compare to orig crash? warn if different?
				# XXX: print out how small the reduced testcase is
				# XXX: log it to the grinder server?
			else
				print_error( "Error, failed to reduce the testcase." )
			end
		end

		begin
			::Process.kill( "KILL", continue_pid )
		rescue ::Errno::ESRCH
		end
		
		if( success and @save_file )
			begin
				::File.open( @save_file, 'w' ) do | dest |
					dest.write( @xmlcrashlog.generate_html( @opts, @elems ? @elems.skipping : [], @idxs ? @idxs.skipping : [] ) )
				end
				print_status( "Saved the testcase to '#{@save_file}'." )
			rescue
				print_error( "Error, failed to save the testcase to '#{@save_file}'." )
			end
		end
		
		return success		
	end
	
	
end

if( $0 == __FILE__ )

	verbose = true
	
	if( ARGV.include?( '--help' ) or ARGV.include?( '-h' ) or ARGV.include?( '/h' ) or ARGV.include?( '/help' ) )
		print_simple( "Usage: >ruby.exe reduction.rb [options] [--verify | --reduce] --browser=BROWSER --hash=XXXXXXXX.XXXXXXXX --log=FILE" )
		print_simple( "  --config=FILE               Specify an alternative config file to use." )
		print_simple( "  --verify                    Verify a log file can reproduce the crash." )
		print_simple( "  --reduce                    Reduce the log file to the smallest log file to still reproduce a crash." )
		print_simple( "  --browser=BROWSER           The browser to perform the reduction on (e.g. IE, CM, FF, SF)." )
		print_simple( "  --log=FILE                  The path to a log file (either encrypted or unencrypted)." )
		print_simple( "  --save=FILE                 The path to a save toe reduced/verified testcase to." )
		print_simple( "  --hash=XXXXXXXX.XXXXXXXX    The origional crash hash you wish to verify/reduce" )
		print_simple( "  --quiet                     Don't print any status/error messages to stdout" )
		print_simple( "  --key=PRIVATEKEY.PEM        If the input log file is encrypted, use a private key to decrypt" )
		print_simple( "  --keypass=PASSPHRASE        Sepcify a pass phrase if the private key requires one" )
		::Kernel.exit( true )
	elsif( ARGV.include?( '--version' ) or ARGV.include?( '-v' ) or ARGV.include?( '/v' ) or ARGV.include?( '/version' ) )
		print_simple( "Version #{$version_major}.#{$version_minor}#{$version_dev ? '-Dev' : '' }" )
		::Kernel.exit( true )
	elsif( ARGV.include?( '--quiet' ) or ARGV.include?( '-q' ) or ARGV.include?( '/q' ) or ARGV.include?( '/quiet' ) )
		verbose = false
	end

	print_init( 'REDUCTION', verbose )

	print_status( "Starting at #{::Time.new.strftime( "%Y-%m-%d %H:%M:%S" )}" )
	
	reduction = Reduction.new( ARGV )
	
	success = reduction.run
	
	print_status( "Finished at #{::Time.new.strftime( "%Y-%m-%d %H:%M:%S" )}" )

	::Kernel::exit( success )
end