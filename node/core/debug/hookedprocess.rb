#
# Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
# Licensed under a 3 clause BSD license (Please see LICENSE.txt)
# Source code located at https://github.com/stephenfewer/grinder
#

require 'lib/metasm/metasm'
require 'core/logging'
require 'core/debug/processsymbols'

module Grinder

	module Core
	
		module Debug
		
			class HookedProcess < Grinder::Core::Debug::ProcessSymbols
				
				attr_accessor :all_loaded, :appverifier, :debugstrings, :commandline, :jscript_loaded
				
				attr_accessor :logger_injected, :logger_loaded, :logmessage, :logmessage2, :finishedtest, :startingtest
				
				attr_accessor :heaphook_injected, :heaphook_loaded, :heap_logmodule, :heap_flush, :heap_defaultalertcallback, :heap_records

				def initialize( pid, handle )
					super( pid, handle )
					
					@all_loaded                = false
					@appverifier               = false
					@debugstrings              = []
					@commandline               = ''
					@jscript_loaded            = false
					
					@logger_injected           = false
					@logger_loaded             = false
					@logmessage                = nil
					@logmessage2               = nil
					@finishedtest              = nil
					@startingtest              = nil
					
					@heaphook_injected         = false
					@heaphook_loaded           = false
					@heap_logmodule            = nil
					@heap_flush                = nil
					@heap_defaultalertcallback = nil
					@heap_records              = nil
				end
				
			end
		
		end
		
	end
	
end
