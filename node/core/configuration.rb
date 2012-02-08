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