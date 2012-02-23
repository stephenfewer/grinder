#
# Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
# Licensed under a 3 clause BSD license (Please see LICENSE.txt)
# Source code located at https://github.com/stephenfewer/grinder
#

$:.unshift('.')

require 'core/configuration'
require 'core/logging'
require 'core/xmlcrashlog'
require 'core/crypt'

class Testcase

	def initialize( arguments )

		@config_file = 'config'
		@log_file    = nil
		@save_file   = nil
		@skip_elem   = ::Array.new
		@key         = nil
		@keypass     = nil
		
		# default options which can be changed via command line. For all the options available, refer to config.rb
		@opts = {
			'try_catch'                 => true,
			'print_code_comments'       => true,
			'print_message_comments'    => true,
			'uncomment_code_comments'   => false
		}

		arguments.each do | arg |
			if( arg.include?( '--config=' ) )
				@config_file = arg[9,arg.length]
			elsif( arg.include?( '--key=' ) )
				@key = arg[6,arg.length]
			elsif( arg.include?( '--keypass=' ) )
				@keypass = arg[10,arg.length]
			elsif( arg.include?( '--log=' ) )
				@log_file = arg[6,arg.length]
			elsif( arg.include?( '--save=' ) )
				@save_file = arg[7,arg.length]
			elsif( arg.start_with?( '-id_' ) )
				@skip_elem << arg.gsub( '-id_', 'id_' )
			else
				case arg
					when '-try'
						@opts['try_catch'] = false
					when '-codecomments'
						@opts['print_code_comments'] = false	
					when '-messagecomments'
						@opts['print_message_comments'] = false	
					when '-comments'
						@opts['print_code_comments'] = @opts['print_message_comments'] = false	
					when '+uncommentcode'
						@opts['uncomment_code_comments'] = true
				end
			end
		end

	end
	
	def systest
	
		if( not config_test() )
			return false
		end
		
		if( not @log_file )
			print_error( "A valid log file has not been specified. Use the --log=FILE param." )
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
		
		xmlcrashlog = XmlCrashLog.new( @log_file, @key, @keypass )
		
		if( not xmlcrashlog.parse )
			print_error( "Error, Failed to parse the xml crash log file '#{@log_file}'." )
			return false
		end
		
		# merge in the command line options over the options from the config file.
		@opts = $testcase_opts.merge( @opts )
		
		html = xmlcrashlog.generate_html( @opts, @skip_elem )
		
		if( @save_file )
			::File.open( @save_file, 'w' ) do | dest |
				dest.write( html )
			end
			
			print_status( "Generated and saved the testcase to '#{@save_file}'." )
		else
			print_simple( html )
		end

		return true		
	end
end

if( $0 == __FILE__ )
	
	verbose = true
	
	if( ARGV.include?( '--help' ) or ARGV.include?( '-h' ) or ARGV.include?( '/h' ) or ARGV.include?( '/help' ) )
		print_simple( "Usage: >ruby.exe testcase.rb [--config=FILE] [--save=FILE] [options] --log=FILE" )
		print_simple( "  --config=FILE           Specify an alternative config file to use." )
		print_simple( "  --log=FILE              The path of a log file to generate the testcase from." )
		print_simple( "  --save=FILE             The file to save the generated tetcase to (If not specified will print to stdout)." )
		print_simple( "  --quiet                 Don't print any status/error messages to stdout" )
		print_simple( "  --key=PRIVATEKEY.PEM    If the input log file is encrypted, use a private key to decrypt" )
		print_simple( "  --keypass=PASSPHRASE    Sepcify a pass phrase if the private key requires one" )
		print_simple( "  -try                    Do not surround all lines in try/catch statements." )
		print_simple( "  -comments               Do not include any commented statements (either code or messages)." )
		print_simple( "  -codecomments           Do not include any commented code statements (/* ...code... */)." )
		print_simple( "  -messagecomments        Do not include any commented message statements (// ...message...)." )
		::Kernel.exit( true )
	elsif( ARGV.include?( '--version' ) or ARGV.include?( '-v' ) or ARGV.include?( '/v' ) or ARGV.include?( '/version' ) )
		print_simple( "Version #{$version_major}.#{$version_minor}#{$version_dev ? '-Dev' : '' }" )
		::Kernel.exit( true )
	elsif( ARGV.include?( '--quiet' ) or ARGV.include?( '-q' ) or ARGV.include?( '/q' ) or ARGV.include?( '/quiet' ) )
		verbose = false
	end

	print_init( 'TESTCASE', verbose )

	print_status( "Starting at #{::Time.new.strftime( "%Y-%m-%d %H:%M:%S" )}" )
	
	testcase = Testcase.new( ARGV )
	
	success = testcase.run
	
	print_status( "Finished at #{::Time.new.strftime( "%Y-%m-%d %H:%M:%S" )}" )
	
	::Kernel::exit( success )
end