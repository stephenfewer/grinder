#
# Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
# Licensed under a 3 clause BSD license (Please see LICENSE.txt)
# Source code located at https://github.com/stephenfewer/grinder
#

$:.unshift('.')

require 'core/logging'
require 'core/xmlcrashlog'

class Testcase

	def initialize( arguments )

		@log_file  = nil
		
		@save_file = nil

		@skip_elem = []

		testcase_prepend = %Q|
				var bigbuff = '';
				var dynamic_params = [];
				for( var b=0 ; b<1111 ; b++ ) { bigbuff += unescape( '%u4141%u4141' ); }
		|

		testcase_fixups = {
			']( , '         => ']( \'\', ',
			' = ;'          => ' = \'\';',
			',  );'         => ', \'\' );',
			'BBBB'          => '\'BBBB\'',
			'<div>'         => '\'<div>\'',
			'ohhh<p>no</p>' => '\'ohhh<p>no</p>\'',
			'?'*2222        => 'bigbuff'
		}
		
		@opts = {
			# surround each logged javascript line in the testcase() function with a try/catch block
			'try_catch'                 => true,
			# if a single log message just contains a comment, print it or not.
			# Note: code snippits should be commented with /* ...code... */ while normal comment messages should be commented with // ...message...
			'print_code_comments'       => true,
			'print_message_comments'    => true,
			# include the following inside the testcases <style>...</style>
			'testcase_style'            => "v\:* { behavior: url(#default#VML); }",
			# include the following inside the testcases <script>...</script>
			'testcase_script'           => '',
			# include the following at the begining of the testcases testcase() function
			'testcase_prepend_function' => testcase_prepend,
			# include the following at the end of the testcases testcase() function
			'testcase_append_function'  => '',
			# help fixup any issues with your testcases by gsubbing the key with the value (handy if you previously miss-logged something)
			'testcase_fixups'           => testcase_fixups,
			# include the following inside the testcases <head>...</head>
			'testcase_head'             => '',
			# include the following inside the testcases <body>...</body>
			'testcase_body'             => "<div id='zoo'></div>"
		}

		arguments.each do | arg |
			if( arg.include?( '--log=' ) )
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
				end
			end
		end

	end
	
	def systest
	
		if( not @log_file )
			print_error( "A valid log file has not been specified. Use the --log=FILE param." )
			return false
		end
		
		if( not ::File.exist?( @log_file ) )
			print_error( "Failed to open the log file '#{@log_file}'." )
			return false
		end
		
		return true
	end
	
	def run
	
		if( not systest() )
			print_error( "System test failed! Please ensure this Grinder node is installed correctly." )
			return false
		end
		
		xmlcrashlog = XmlCrashLog.new( @log_file )
		
		if( not xmlcrashlog.parse )
			print_error( "Error, Failed to parse the xml crash log file '#{@log_file}'." )
			return false
		end
		
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
		print_simple( "Usage: >ruby.exe testcase.rb [options] [--save=FILE] --log=FILE" )
		print_simple( "  --log=FILE          The path of a log file to generate the testcase from." )
		print_simple( "  --save=FILE         The file to save the generated tetcase to (If not specified will print to stdout)." )
		print_simple( "  --quiet             Don't print any status/error messages to stdout" )
		print_simple( "  -try                Do not surround all lines in try/catch statements." )
		print_simple( "  -comments           Do not include any commented statements (either code or messages)." )
		print_simple( "  -codecomments       Do not include any commented code statements (/* ...code... */)." )
		print_simple( "  -messagecomments    Do not include any commented message statements (// ...message...)." )
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