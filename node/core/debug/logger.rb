#
# Copyright (c) 2014, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
# Licensed under a 3 clause BSD license (Please see LICENSE.txt)
# Source code located at https://github.com/stephenfewer/grinder
#

module Grinder

	module Core
	
		module Debug
		
			module Logger
			
				def logger_initialize( logdir=nil )
					@logger_dll = "grinder_logger.dll"
					@logdir     = logdir ? logdir : ENV['TEMP']
				end
				
				def use_logger?( pid )
					return true
				end
				
				def logger_file( pid )
					gen_logger_filename( "logger_#{ pid }" )
				end
				
				def gen_logger_filename( name )
					"#{ @logdir }#{ @logdir.end_with?('\\') ? '' : '\\' }#{ name }.xml"
				end
				
				def loader_logger( imagebase )
					print_status( "Logger DLL loaded into process #{@pid} @ 0x#{'%X' % imagebase }")
					
					setlogfile = get_dll_export( imagebase, 'LOGGER_setLogFile' )
					if( setlogfile )
						file = logger_file( @pid )
						file_addr = ::Metasm::WinAPI.virtualallocex( @os_process.handle, 0, file.length, ::Metasm::WinAPI::MEM_COMMIT|Metasm::WinAPI::MEM_RESERVE, ::Metasm::WinAPI::PAGE_READWRITE )
						@os_process.memory[file_addr, file.length] = file
						::Metasm::WinAPI.createremotethread( @attached[@pid].handle, 0, 0, setlogfile, file_addr, 0, 0 )
						print_status( "Logging process #{@pid} to log file '#{file}'" )
					else
						print_error( "Failed to resolved grinder_logger!LOGGER_setLogFile" )
					end
					
					if( not @attached[@pid].logmessage )
						logmessage = get_dll_export( imagebase, 'LOGGER_logMessage' )
						if( logmessage )
							@attached[@pid].logmessage = logmessage
						else
							print_error( "Failed to resolved grinder_logger!LOGGER_logMessage" )
						end
					end
					
					if( not @attached[@pid].logmessage2 )
						logmessage2 = get_dll_export( imagebase, 'LOGGER_logMessage2' )
						if( logmessage2 )
							@attached[@pid].logmessage2 = logmessage2
						else
							print_error( "Failed to resolved grinder_logger!LOGGER_logMessage2" )
						end
					end
					
					if( not @attached[@pid].startingtest )
						startingtest = get_dll_export( imagebase, 'LOGGER_startingTest' )
						if( startingtest )
							@attached[@pid].startingtest = startingtest
						else
							print_error( "Failed to resolved grinder_logger!LOGGER_startingTest" )
						end
					end
					
					if( not @attached[@pid].finishedtest )
						finishedtest = get_dll_export( imagebase, 'LOGGER_finishedTest' )
						if( finishedtest )
							@attached[@pid].finishedtest = finishedtest
						else
							print_error( "Failed to resolved grinder_logger!LOGGER_finishedTest" )
						end
					end
					
					if( setlogfile and @attached[@pid].logmessage and @attached[pid].logmessage2 and @attached[@pid].startingtest and @attached[@pid].finishedtest )
						return true
					end
					
					return false
				end
				
			end
	
		end
	
	end

end
