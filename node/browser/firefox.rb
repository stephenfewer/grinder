#
# Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
# Licensed under a 3 clause BSD license (Please see LICENSE.txt)
# Source code located at https://github.com/stephenfewer/grinder
#

require 'core/configuration'
require 'core/debugger'

module Grinder

	module Browser
	
		# https://developer.mozilla.org/en/How_to_get_a_stacktrace_with_WinDbg
		
		# Note: In about:config set dom.max_script_run_time to something like 600 to avoid stop script dialogs...
		
		class FireFox < Grinder::Core::Debugger
			
			def extra_symbol_server
				return 'http://symbols.mozilla.org/firefox'
			end
			
			def loaders( pid, path, addr )
				if( path.include?( 'mozjs' ) )
					@browser = 'FF'
					if( not @attached[pid].jscript_loaded )
						@attached[pid].jscript_loaded = loader_javascript( pid, addr )
					end
				end
				@attached[pid].all_loaded = @attached[pid].jscript_loaded
			end

			def loader_javascript( pid, imagebase )
				print_status( "mozjs.dll DLL loaded into process #{pid} @ 0x#{'%08X' % imagebase }" )
				
				if( not @attached[pid].logmessage or not @attached[pid].finishedtest )
					print_error( "Unable to hook JavaScript parseFloat() in process #{pid}, logger dll not injected." )
					return false
				end
				
				symbol = 'mozjs!num_parseFloat'
				
				# hook mozjs!num_parseFloat to call LOGGER_logMessage/LOGGER_finishedTest
				parsefloat = @attached[pid].name2address( imagebase, 'mozjs.dll', symbol )
				if( not parsefloat )
					print_error( "Unable to resolved #{symbol}" )
					return false
				end
				
				print_status( "Resolved #{symbol} @ 0x#{'%08X' % parsefloat }" )

				cpu        = Metasm::Ia32.new
				
				code       = @mem[pid][parsefloat,512]

				found      = false
				
				patch_size = 0
				
				# we first disasemble the function looking for the first call (to mozjs!js_ValueToString)
				# once found we want to place out hook after this function call as it
				# resolves the input parameter to its unicode string for us. We then
				# calculate the number of instructions after the call which we will
				# overwrite (to avoid munging half an instruction)
				Metasm::Shellcode.disassemble( cpu, code ).decoded.each_value do | di |
					if( not found and di.opcode.name.downcase == 'call' ) # XXX: we should sanity check this is actually for mozjs!js_ValueToString
						parsefloat += di.address + di.bin_length
						found = true
						next
					end
					if( found )
						break if patch_size >= 5
						patch_size += di.bin_length
					end
				end

				if( not found or patch_size < 5 )
					print_error( "Unable to locate the location to insert the hook" )
					return false
				end
				
				backup     = @mem[pid][parsefloat,patch_size]
				
				proxy_addr = Metasm::WinAPI.virtualallocex( @hprocess[pid], 0, 1024, Metasm::WinAPI::MEM_COMMIT|Metasm::WinAPI::MEM_RESERVE, Metasm::WinAPI::PAGE_EXECUTE_READWRITE )
				
				# we hook inside the function (not the prologue) after a call to resolve the string parameter...
				proxy = Metasm::Shellcode.assemble( cpu, %Q{
					pushfd
					pushad
					mov ebx, [eax+4]
					lea eax, [ebx+4]
					mov ebx, [ebx]
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

	ARGV.each do | arg |
		if( arg.include?( '--config=' ) )
			config_file = arg[9,arg.length]
			
			if( not config_init( config_file ) )
				print_error( "Failed to load the config file '#{config_file}'." )
				::Kernel::exit( false )
			end	
		end
	end
	
	Grinder::Core::Debugger.main( $firefox_exe, Grinder::Browser::FireFox )

end
