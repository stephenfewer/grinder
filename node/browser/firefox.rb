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
			
			def self.target_exe
				return $firefox_exe
			end
			
			def extra_symbol_server
				return 'http://symbols.mozilla.org/firefox'
			end
			
			@@cached_major_version = -1
			@@cached_minor_version = -1
			
			def ff_version
				begin
					if( @@cached_major_version != -1 )
						return true
					end
					pe = Metasm::PE.decode_file_header( FireFox.target_exe )
					version = pe.decode_version
					if( version['FileVersion'] )
						result = version['FileVersion'].scan( /(\d*).(\d*)/ )
						@@cached_major_version = result.first[0].to_i
						@@cached_minor_version = result.first[1].to_i
						return true
					end
				rescue
				end
				return false
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
				
				if( not ff_version )
					print_error( "Unable to determind FireFox version for hooking." )
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

				symbol = 'mozjs!js_strtod'
				
				js_strtod = @attached[pid].name2address( imagebase, 'mozjs.dll', symbol )
				if( not js_strtod )
					print_error( "Unable to resolved #{symbol}" )
					return false
				end
				
				print_status( "Resolved #{symbol} @ 0x#{'%08X' % js_strtod }" )

				cpu        = Metasm::Ia32.new
				
				code       = @mem[pid][parsefloat,512]

				found      = false
				
				patch_size = 0
				
				# we first disassemble the function looking for the first call to mozjs!js_strtod.
				# once found we want to place out hook after this function call as it
				# resolves the input parameter to its unicode string for us. We then
				# calculate the number of instructions after the call which we will
				# overwrite (to avoid munging half an instruction)
				
				eip = parsefloat
				
				js_strtod_string_reg = nil
				
				# Note: We dont use "Metasm::Shellcode.disassemble( cpu, code ).decoded.each_value do | di |"
				# as this will follow conditional jumps and we need a simple linear disassembly
				while true do
					di = cpu.decode_instruction( ::Metasm::EncodedData.new( code ), eip )

					eip += di.bin_length
					
					code = code[ di.bin_length, code.length ]
					
					if( not found and di.opcode.name.downcase == 'push' ) 
						js_strtod_string_reg = di.instruction.args[0].to_s.downcase
					elsif( not found and di.opcode.name.downcase == 'call' ) 
						# check this is a call to mozjs!js_strtod
						if( di.instruction.args[0].to_s.to_i(16) == js_strtod )
							parsefloat = di.address + di.bin_length
							found = true
							# js_strtod_string_reg will now be the last push param before the call to js_strtod
						end
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
				
				print_status( "call to js_strtod @ 0x#{'%08X' % parsefloat }" )
				
				backup     = @mem[pid][parsefloat,patch_size]
				
				proxy_addr = Metasm::WinAPI.virtualallocex( @hprocess[pid], 0, 1024, Metasm::WinAPI::MEM_COMMIT|Metasm::WinAPI::MEM_RESERVE, Metasm::WinAPI::PAGE_EXECUTE_READWRITE )
				
				fixup      = ''
				
				if( @@cached_major_version == 23 ) # Tested against FF 23.0.1
					js_strtod_string_reg = 'esi' if not js_strtod_string_reg
					
					fixup = %Q{
						test #{js_strtod_string_reg}, #{js_strtod_string_reg}
						jz passthru_end2
						mov eax, #{js_strtod_string_reg}
					}
				elsif( @@cached_major_version == 18 ) # Tested against FF 18.0
					fixup = %Q{
						test ebx, ebx
						jz passthru_end2
						mov eax, ebx
					}
				elsif( @@cached_major_version == 17 ) # Tested against FF 17.0.1
					fixup = %Q{
						test edi, edi
						jz passthru_end2
						mov eax, [edi+4]
					}
				else
					fixup = %Q{
						test edi, edi
						jz passthru_end2
						mov eax, edi
					}
				end
				
				# we hook inside the function (not the prologue) after a call to resolve the string parameter...
				proxy = Metasm::Shellcode.assemble( cpu, %Q{
					pushfd
					pushad
					
					#{ fixup }
					
					mov ebx, [eax]
					lea eax, [eax+4]
					push eax
					cmp ebx, 0xDEADCAFE
					jne passthru1
					pop eax
					push dword [eax]
					lea eax, [eax+4]
					push eax
					mov edi, 0x#{ '%08X' % @attached[pid].logmessage2 }
					call edi
					pop eax
					jmp passthru_end
				passthru1:
					cmp ebx, 0xDEADC0DE
					jne passthru2
					mov edi, 0x#{ '%08X' % @attached[pid].logmessage }
					call edi
					jmp passthru_end
				passthru2:
					cmp ebx, 0xDEADF00D
					jne passthru3
					mov edi, 0x#{ '%08X' % @attached[pid].finishedtest }
					call edi
					jmp passthru_end
				passthru3:
					cmp ebx, 0xDEADBEEF
					jne passthru4
					mov edi, 0x#{ '%08X' % @attached[pid].startingtest }
					call edi
				passthru4:
					cmp ebx, 0xDEADDEAD
					jne passthru_end
					mov [ebx], ebx
				passthru_end:
					pop eax
				passthru_end2:
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

	Grinder::Core::Debugger.main( Grinder::Browser::FireFox, ARGV )

end
