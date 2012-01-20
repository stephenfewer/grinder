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
				
				attr_accessor :all_loaded, :logger_injected, :logger_loaded, :jscript_loaded, :logmessage, :finishedtest
				
				def initialize( pid, handle )
					super( pid, handle )
					@all_loaded      = false
					@logger_injected = false
					@logger_loaded   = false
					@jscript_loaded  = false
					@logmessage      = nil
					@finishedtest    = nil
				end
				
			end
		
		end
		
	end
	
end
