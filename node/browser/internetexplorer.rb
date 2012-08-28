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
			
			@@cached_version = -1
			
			def ie_major_version
				begin
					if( @@cached_version != -1 )
						return @@cached_version
					end
					pe = Metasm::PE.decode_file_header( InternetExplorer.target_exe )
					version = pe.decode_version
					if( version['FileVersion'] )
						result = version['FileVersion'].scan( /(\d*)/ )
						@@cached_version = result.first.first.to_i
						return @@cached_version
					end
				rescue
				end
				return -1
			end
			
			def self.target_exe
				return $internetexplorer_exe
			end
			
			def heaphook_modules
				if( $internetexplorer_logmods )
					return $internetexplorer_logmods
				end
				return []
			end
			
			# we dont want to use grinder_heaphook.dll in the broker process...
			def use_heaphook?( pid )
				if( ie_major_version == 8 )
					return true
				elsif( ie_major_version >= 9 && @attached[pid].commandline =~ /SCODEF:/i )
					return true
				end
				return false
			end
			
			# we dont want to use grinder_logger.dll in the broker process...
			def use_logger?( pid )
				if( ie_major_version == 8 )
					return true
				elsif( ie_major_version >= 9 && @attached[pid].commandline =~ /SCODEF:/i )
					return true
				end
				return false
			end
			
			def loaders( pid, path, addr )
				@browser = "IE" + ie_major_version.to_s
				
				if( path.include?( 'jscript9' ) )
					# IE10 (Windows 8 Consumer Preview) uses the module jscript9.dll but we
					# exhamine the version number to determine if its actually IE10 or IE9.
					if( not @attached[pid].jscript_loaded )
						@attached[pid].jscript_loaded = loader_javascript_ie9( pid, addr )
					end
				elsif( path.include?( 'jscript' ) )
					if( not @attached[pid].jscript_loaded )
						@attached[pid].jscript_loaded = loader_javascript_ie8( pid, addr )
					end
				end
				
				@attached[pid].all_loaded = @attached[pid].jscript_loaded
			end
			
			def loader_javascript_ie9( pid, imagebase )
				print_status( "jscript9.dll DLL loaded into process #{pid} @ 0x#{'%08X' % imagebase }" )
				
				if( not @attached[pid].logmessage or not @attached[pid].finishedtest )
					print_error( "Unable to hook JavaScript parseFloat() in process #{pid}, grinder_logger.dll not injected." )
					return false
				end
				
				symbol = 'jscript9!StrToDbl<unsigned short>'
				
				# hook jscript9!StrToDbl to call LOGGER_logMessage/LOGGER_finishedTest
				strtodbl = @attached[pid].name2address( imagebase, 'jscript9.dll', symbol )
				if( not strtodbl )
					print_error( "Unable to resolved #{symbol}" )
					return false
				end
				
				print_status( "Resolved jscript!StrToDbl @ 0x#{'%08X' % strtodbl }" )
				
				cpu        = Metasm::Ia32.new
				
				patch_size = 5
				
				backup     = @mem[pid][strtodbl,patch_size]
				
				proxy_addr = Metasm::WinAPI.virtualallocex( @hprocess[pid], 0, 1024, Metasm::WinAPI::MEM_COMMIT|Metasm::WinAPI::MEM_RESERVE, Metasm::WinAPI::PAGE_EXECUTE_READWRITE )
				
				proxy = Metasm::Shellcode.assemble( cpu, %Q{
					pushfd
					pushad
					mov eax, [esp+0x04+0x24]
					
					mov ebx, [eax]
					lea eax, [eax+4]
					push eax
					cmp ebx, 0xDEADCAFE
					jne passthru1
					pop eax
					push dword [eax]
					lea eax, [eax+4]
					push eax
					mov edi, 0x#{'%08X' % @attached[pid].logmessage2 }
					call edi
					pop eax
					jmp passthru_end
				passthru1:
					cmp ebx, 0xDEADC0DE
					jne passthru2
					mov edi, 0x#{'%08X' % @attached[pid].logmessage }
					call edi
					jmp passthru_end
				passthru2:
					cmp ebx, 0xDEADF00D
					jne passthru3
					mov edi, 0x#{'%08X' % @attached[pid].finishedtest }
					call edi
					jmp passthru_end
				passthru3:
					cmp ebx, 0xDEADBEEF
					jne passthru4
					mov edi, 0x#{'%08X' % @attached[pid].startingtest }
					call edi
				passthru4:
					cmp ebx, 0xDEADDEAD
					jne passthru_end
					mov [ebx], ebx
				passthru_end:
					pop eax
					popad
					popfd
				} ).encode_string

				proxy << backup
				
				proxy << jmp5( (strtodbl+backup.length), (proxy_addr+proxy.length) )
				
				@mem[pid][proxy_addr, proxy.length] = proxy
				
				@mem[pid][strtodbl,patch_size]      = jmp5( proxy_addr, strtodbl ) + "\x90" * (patch_size - 5)
				
				print_status( "Hooked JavaScript parseFloat() to grinder_logger.dll via proxy @ 0x#{'%08X' % proxy_addr }" )
				
				return true
			end
			
			def loader_javascript_ie8( pid, imagebase )
				print_status( "jscript.dll DLL loaded into process #{pid} at address 0x#{'%08X' % imagebase }" )
				
				if( not @attached[pid].logmessage or not @attached[pid].finishedtest )
					print_error( "Unable to hook JavaScript parseFloat() in process #{pid}, grinder_logger.dll not injected." )
					return false
				end
				
				symbol   = 'jscript!StrToDbl'
				
				# hook jscript!StrToDbl to call LOGGER_logMessage/LOGGER_finishedTest
				strtodbl = @attached[pid].name2address( imagebase, 'jscript.dll', symbol )
				if( not strtodbl )
					print_error( "Unable to resolved #{symbol}" )
					return false
				end
				
				print_status( "Resolved jscript!StrToDbl @ 0x#{'%08X' % strtodbl }" )
				
				cpu        = Metasm::Ia32.new
				
				patch_size = 5
				
				backup     = @mem[pid][strtodbl,patch_size]
				
				proxy_addr = Metasm::WinAPI.virtualallocex( @hprocess[pid], 0, 1024, Metasm::WinAPI::MEM_COMMIT|Metasm::WinAPI::MEM_RESERVE, Metasm::WinAPI::PAGE_EXECUTE_READWRITE )
				
				proxy = Metasm::Shellcode.assemble( cpu, %Q{
					pushfd
					pushad
					mov eax, [esp+0x38+0x24]
					
					mov ebx, [eax]
					lea eax, [eax+4]
					push eax
					cmp ebx, 0xDEADCAFE
					jne passthru1
					pop eax
					push dword [eax]
					lea eax, [eax+4]
					push eax
					mov edi, 0x#{'%08X' % @attached[pid].logmessage2 }
					call edi
					pop eax
					jmp passthru_end
				passthru1:
					cmp ebx, 0xDEADC0DE
					jne passthru2
					mov edi, 0x#{'%08X' % @attached[pid].logmessage }
					call edi
					jmp passthru_end
				passthru2:
					cmp ebx, 0xDEADF00D
					jne passthru3
					mov edi, 0x#{'%08X' % @attached[pid].finishedtest }
					call edi
					jmp passthru_end
				passthru3:
					cmp ebx, 0xDEADBEEF
					jne passthru4
					mov edi, 0x#{'%08X' % @attached[pid].startingtest }
					call edi
				passthru4:
					cmp ebx, 0xDEADDEAD
					jne passthru_end
					mov [ebx], ebx
				passthru_end:
					pop eax
					popad
					popfd
				} ).encode_string

				proxy << backup
				
				proxy << jmp5( (strtodbl+backup.length), (proxy_addr+proxy.length) )
				
				@mem[pid][proxy_addr, proxy.length] = proxy
				
				@mem[pid][strtodbl,patch_size]      = jmp5( proxy_addr, strtodbl ) + "\x90" * (patch_size - 5)
				
				print_status( "Hooked JavaScript parseFloat() to grinder_logger.dll via proxy @ 0x#{'%08X' % proxy_addr }" )
				
				return true
			end
			
		end

	end

end

if( $0 == __FILE__ )

	Grinder::Core::Debugger.main( Grinder::Browser::InternetExplorer, ARGV )

end
