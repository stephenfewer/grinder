#
# Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
# Licensed under a 3 clause BSD license (Please see LICENSE.txt)
# Source code located at https://github.com/stephenfewer/grinder
#

require 'core/configuration'
require 'core/debugger'

module Grinder

	module Browser
	
		class Chrome < Grinder::Core::Debugger
			
			def self.target_exe
				return $chrome_exe
			end
			
			def extra_param
				return '--no-sandbox'
			end
			
			def extra_symbol_server
				return 'http://chromium-browser-symsrv.commondatastorage.googleapis.com'
			end
			
			def loaders( pid, path, addr )
				if( path.include?( 'chrome.dll' ) )
					@browser = 'CM'
					if( not @attached[pid].jscript_loaded )
						@attached[pid].jscript_loaded = loader_javascript_chrome( pid, addr, 'chrome.dll' )
					end
				elsif( path.include?( 'chrome_child.dll' ) )
					@browser = 'CM'
					if( not @attached[pid].jscript_loaded )
						@attached[pid].jscript_loaded = loader_javascript_chrome( pid, addr, 'chrome_child.dll' )
					end
				end
				@attached[pid].all_loaded = @attached[pid].jscript_loaded
			end
			
			# hook chrome.dll!v8::internal::Runtime_StringParseFloat to call LOGGER_logMessage/LOGGER_finishedTest
			def loader_javascript_chrome( pid, imagebase, chrome_dll )
				print_status( "#{chrome_dll} DLL loaded into process #{pid} at address 0x#{'%08X' % imagebase }" )
				
				if( not @attached[pid].logmessage or not @attached[pid].finishedtest )
					print_error( "Unable to hook JavaScript parseFloat() in process #{pid}, grinder_logger.dll not injected." )
					return false
				end
				
				symbol     = 'v8::internal::Runtime_StringParseFloat'
				
				parsefloat = @attached[pid].name2address( imagebase, chrome_dll, symbol )
				
				if( not parsefloat )
					print_error( "Unable to resolved #{chrome_dll}!#{symbol}")
					return false
				end
				
				print_status( "Resolved #{chrome_dll}!#{symbol} @ 0x#{'%08X' % parsefloat }" )
				
				cpu        = Metasm::Ia32.new
				
				patch_size = 6
				
				backup     = @mem[pid][parsefloat,patch_size]
				
				proxy_addr = Metasm::WinAPI.virtualallocex( @hprocess[pid], 0, 1024, Metasm::WinAPI::MEM_COMMIT|Metasm::WinAPI::MEM_RESERVE, Metasm::WinAPI::PAGE_EXECUTE_READWRITE )
				
				proxy = Metasm::Shellcode.assemble( cpu, %Q{
					pushfd
					pushad
					mov eax,dword ptr [esp+0x08+0x24]
					mov eax,dword ptr [eax]
					lea eax, [eax+0x0B]
					
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
				
				proxy << jmp5( (parsefloat+backup.length), (proxy_addr+proxy.length) )
				
				@mem[pid][proxy_addr, proxy.length] = proxy
				
				@mem[pid][parsefloat,patch_size]    = jmp5( proxy_addr, parsefloat ) + "\x90" * (patch_size - 5)
				
				print_status( "Hooked JavaScript parseFloat() to grinder_logger.dll via proxy @ 0x#{'%08X' % proxy_addr }" )
				
				return true
			end
			
		end

	end

end

if( $0 == __FILE__ )

	Grinder::Core::Debugger.main( Grinder::Browser::Chrome, ARGV )

end
