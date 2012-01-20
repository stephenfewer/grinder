#
# Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
# Licensed under a 3 clause BSD license (Please see LICENSE.txt)
# Source code located at https://github.com/stephenfewer/grinder
#

require 'core/configuration'
require 'core/debugger'

module Grinder

	module Browser
	
		class InternetExplorer < Grinder::Core::Debugger
			
			def loaders( pid, path, addr )
				if( path.include?( 'jscript9' ) )
					@browser = "IE9"
					if( not @attached[pid].jscript_loaded )
						@attached[pid].jscript_loaded = loader_javascript_ie9( pid, addr )
					end
				elsif( path.include?( 'jscript' ) )
					@browser = "IE8"
					if( not @attached[pid].jscript_loaded )
						@attached[pid].jscript_loaded = loader_javascript_ie8( pid, addr )
					end
				end
				
				@attached[pid].all_loaded = @attached[pid].jscript_loaded
			end
			
			def loader_javascript_ie9( pid, imagebase )
				print_status( "jscript9.dll DLL loaded into process #{pid} @ 0x#{'%08X' % imagebase }")
				# hook jscript9!StrToDbl to call LOGGER_logMessage/LOGGER_finishedTest
				strtodbl = @attached[pid].name2address( imagebase, 'jscript9.dll', 'jscript9!StrToDbl<unsigned short>' )
				if( strtodbl )

					if( not @attached[pid].logmessage or not @attached[pid].finishedtest )
						print_error( "Unable to hook JavaScript parseFloat() in process #{pid}, logger dll not injected." )
					else
						backup = @mem[pid][strtodbl,5]
								
						proxy_addr = Metasm::WinAPI.virtualallocex( @hprocess[pid], 0, 1024, Metasm::WinAPI::MEM_COMMIT|Metasm::WinAPI::MEM_RESERVE, Metasm::WinAPI::PAGE_EXECUTE_READWRITE )
								
						proxy = Metasm::Shellcode.assemble( Metasm::Ia32.new, %Q{
							pushfd
							pushad
							mov eax, [esp+0x04+0x24]
							mov ebx, [eax]
							lea eax, [eax+4]
							push eax
							cmp ebx, 0xDEADC0DE
							jne passthruA
							mov edi, 0x#{'%08X' % @attached[pid].logmessage }
							call edi
							jmp passthruB
						passthruA:
							cmp ebx, 0xDEADF00D
							jne passthruB
							mov edi, 0x#{'%08X' % @attached[pid].finishedtest }
							call edi
						passthruB:
							pop eax
							popad
							popfd
						} ).encode_string

						proxy << backup
						proxy << jmp5( (strtodbl+backup.length), (proxy_addr+proxy.length) )
								
						@mem[pid][proxy_addr, proxy.length] = proxy
								
						@mem[pid][strtodbl,5] = jmp5( proxy_addr, strtodbl )
								
						print_status( "Hooked JavaScript parseFloat() to grinder_logger.dll via proxy @ 0x#{'%08X' % proxy_addr }")
						return true
					end
				else
					print_serror( "Failed to resolved jscript9!StrToDbl")
				end
				return false
			end
			
			def loader_javascript_ie8( pid, imagebase )
				print_status( "jscript.dll DLL loaded into process #{pid} at address 0x#{'%08X' % imagebase }")
				# hook jscript!StrToDbl to call LOGGER_logMessage/LOGGER_finishedTest
				strtodbl = @attached[pid].name2address( imagebase, 'jscript.dll', 'jscript!StrToDbl' )
				if( strtodbl )
					print_status( "Resolved jscript!StrToDbl @ 0x#{'%08X' % strtodbl }")
							
					if( not @attached[pid].logmessage or not @attached[pid].finishedtest )
						print_error( "Unable to hook JavaScript parseFloat() in process #{pid}, grinder_logger.dll not injected." )
					else
						backup = @mem[pid][strtodbl,5]
								
						proxy_addr = Metasm::WinAPI.virtualallocex( @hprocess[pid], 0, 1024, Metasm::WinAPI::MEM_COMMIT|Metasm::WinAPI::MEM_RESERVE, Metasm::WinAPI::PAGE_EXECUTE_READWRITE )
								
						proxy = Metasm::Shellcode.assemble( Metasm::Ia32.new, %Q{
							pushfd
							pushad
							mov eax, [esp+0x38+0x24]
							mov ebx, [eax]
							lea eax, [eax+4]
							push eax
							cmp ebx, 0xDEADC0DE
							jne passthruA
							mov edi, 0x#{'%08X' % @attached[pid].logmessage }
							call edi
							jmp passthruB
						passthruA:
							cmp ebx, 0xDEADF00D
							jne passthruB
							mov edi, 0x#{'%08X' % @attached[pid].finishedtest }
							call edi
						passthruB:
							pop eax
							popad
							popfd
						} ).encode_string

						proxy << backup
						proxy << jmp5( (strtodbl+backup.length), (proxy_addr+proxy.length) )
								
						@mem[pid][proxy_addr, proxy.length] = proxy
								
						@mem[pid][strtodbl,5] = jmp5( proxy_addr, strtodbl )
								
						print_status( "Hooked JavaScript parseFloat() to grinder_logger.dll via proxy @ 0x#{'%08X' % proxy_addr }")
						return true
					end
				end
				return false
			end
			
		end

	end

end

if( $0 == __FILE__ )

	ARGV.each do | arg |
		if( arg.include?( '--config=' ) )
			config_file = arg[9,arg.length]
			
			if( not config_init( config_file ) )
				print_error( "Failed to load the config file '#{config_file}'." )
				::Kernel::exit( false )
			end			
		end
	end
	
	Grinder::Core::Debugger.main( $internetexplorer_exe, Grinder::Browser::InternetExplorer )

end
