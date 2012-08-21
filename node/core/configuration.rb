#
# Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
# Licensed under a 3 clause BSD license (Please see LICENSE.txt)
# Source code located at https://github.com/stephenfewer/grinder
#

def config_init( config_file )

	begin
		require config_file
		
		# this is instead of trying to call kernel32!GetSystemWow64Directory...
		root = "c:\\windows"
		if( ENV.include?( 'SystemRoot' ) )
			root = ENV[ 'SystemRoot' ]
		end
		
		wow64 = false		
		if( ::Dir.exist?( "#{root}\\syswow64\\" ) )
			wow64 = true
		end
		
		# new additions to config.rb as of v0.3 (this help old config files to still work)
		eval( "$testcases_reduction = true" ) if $testcases_reduction == nil
		
		eval( "$testcase_opts = ::Hash.new" ) if $testcase_opts == nil
		
		eval( "$instrument_heap = false" ) if $instrument_heap == nil
		
		# patch any global vars here...
		global_variables.each do | v | 
			
			if( v == :$= or v == :$KCODE or v == :$-K or v == :$FILENAME )
				next
			end

			res = eval( v.to_s )
			
			if( res.class != ::String )
				next
			end
			
			if( res.include?( '%USERNAME%' ) )
				res = res.gsub( '%USERNAME%', ENV['USERNAME'] )
				if( res.end_with? '\\' )
					res << '\\'
				end
				eval( "#{ v.to_s } = '#{ res }'" )
			elsif( res.include?( '%PROGRAM_FILES_32%' ) )
				res = res.gsub( '%PROGRAM_FILES_32%', wow64 ? 'Program Files (x86)' : 'Program Files' )
				if( res.end_with? '\\' )
					res << '\\'
				end
				eval( "#{ v.to_s } = '#{ res }'" )
			end
			
		end
	rescue
		return false
	end
	
	return true
end

def config_test

	ruby_major = RUBY_VERSION.split( '.' )[0].to_i
	ruby_minor = RUBY_VERSION.split( '.' )[1].to_i

	if( ruby_major < 1 and ruby_minor < 9 )
		print_warning( "Warning, you should be running this on at least Ruby 1.9" )
	end
		
	if( not ::Dir.exist?( $logger_dir ) )
		print_error( "Error, the temporary logging directory ('#{$logger_dir }') does not exist." )
		return false
	end
		
	if( not ::Dir.exist?( $crashes_dir ) )
		print_error( "Error, the Crashes directory ('#{$crashes_dir }') does not exist." )
		return false
	end
		
	if( not ::Dir.exist?( $fuzzers_dir ) )
		print_error( "Error, the Fuzzers directory ('#{$fuzzers_dir }') does not exist." )
		return false
	end
		
	if( not ::Dir.exist?( $symbols_dir ) )
		print_error( "Error, the Symbols directory ('#{$symbols_dir }') does not exist." )
		return false
	end
		
	if( $debugger_restart_minutes < 5 )
		print_warning( "Warning, you have set the debugger to restart every #{$debugger_restart_minutes} minutes, The Grinder Server will see this node as inactive unless you use a value of more than 5 minutes." )
	end
		
	if( $webstats_baseurl and not $webstats_baseurl.end_with?( 'status.php' ) )
		print_warning( "Warning, the URL to your Grinder Server (#{@webstats_baseurl}) does not point to status.php. Please ensure this URL exists on your Grinder Server." )
	end
		
	if( $crashes_encrypt )
		begin
			require 'openssl'
		rescue ::LoadError
			print_error( "Failed to require openssl. Encrypting crashes will not work without it." )
			return false
		end
			
		if( not ::File.exist?( $public_key_file ) )
			print_error( "Failed to open the public key file '#{$public_key_file}'. Encrypting crashes will not work without it." )
			return false
		end
			
		key = OpenSSL::PKey::RSA.new( ::File.read( $public_key_file ) )
		if( not key.public? )
			print_error( "The public key file '#{$public_key_file}' has no public key!" )
			return false
		end
	end
		
	return true
end