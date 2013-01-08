#
# Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
# Licensed under a 3 clause BSD license (Please see LICENSE.txt)
# Source code located at https://github.com/stephenfewer/grinder
#

require 'core/configuration'
require 'core/debugger'

module Grinder

	module Browser
	
		class Safari < Grinder::Core::Debugger
		
			def self.target_exe
				return $safari_exe
			end
			
			def loaders( pid, path, addr )
				if( path.include?( 'javascriptcore.dll' ) )
					@browser = 'SF'
					if( not @attached[pid].jscript_loaded )
						@attached[pid].jscript_loaded = loader_javascript_safari( pid, addr )
					end
				end
				@attached[pid].all_loaded = @attached[pid].jscript_loaded
			end

			# Tested against latest Safari 1.7.1 (7534.57.2)
			def loader_javascript_safari( pid, imagebase )
				print_status( "JavaScriptCore.dll DLL loaded into process #{pid} at address 0x#{'%08X' % imagebase }" )
				
				if( not @attached[pid].logmessage or not @attached[pid].finishedtest )
					print_error( "Unable to hook JavaScript parseFloat() in process #{pid}, logger dll not injected." )
					return false
				end
				
				# hook JavaScriptCore!parseFloat to call LOGGER_logMessage/LOGGER_finishedTest
				
				# this is, errr, one way to do it I guess ;)
				
				# We locate this structure in memroy to resolve the address of parseFloat...
				# .rdata:1012D84C                 dd offset aParsefloat   ; "parseFloat"
				# .rdata:1012D850                 dd 14h
				# .rdata:1012D854                 dd offset sub_10105E26
				
				# first, find the location of the 'parseFloat' string in the images memory
				# WinDbg: s -a JavaScriptCore Lffffff parseFloat
				parsefloat = @mem[pid][ imagebase, 0xFFFFFF ].index('parseFloat')
				if( not parsefloat )
					print_error( "Unable to resolved JavaScriptCore!parseFloat (1)" )
					return false
				end
				parsefloat = imagebase + parsefloat
				
				# next, find the first reference to the pointer to 'parseFloat'
				# WinDbg:  s -d JavaScriptCore Lffffff XXXXXXXX 
				parsefloat = @mem[pid][ imagebase, 0xFFFFFF ].index( [parsefloat].pack('V') )
				if( not parsefloat )
					print_error( "Unable to resolved JavaScriptCore!parseFloat (2)" )
					return false
				end
				parsefloat = imagebase + parsefloat
				
				# finally, the third dword from this address if the address of the parseFloat function!
				parsefloat = @mem[pid][ parsefloat + 8, 4 ]
				if( not parsefloat )
					print_error( "Unable to resolved JavaScriptCore!parseFloat (3)" )
					return false
				end
				
				parsefloat = parsefloat.unpack('V').first
				if( not parsefloat )
					print_error( "Unable to resolved JavaScriptCore!parseFloat (4)" )
					return false
				end
				
				print_status( "Resolved JavaScriptCore!parseFloat @ 0x#{'%08X' % parsefloat }" )

				cpu        = Metasm::Ia32.new
				
				code       = @mem[pid][parsefloat,512]
				
				found      = false
				
				patch_size = 0
				
				# .text:10105E26                 push    ebp
				# .text:10105E27                 mov     ebp, esp
				# .text:10105E29                 and     esp, 0FFFFFFF8h
				# .text:10105E2C                 sub     esp, 14h
				# .text:10105E2F                 push    edi
				# .text:10105E30                 push    ecx
				# .text:10105E31                 lea     eax, [esp+8]
				# .text:10105E35                 push    eax
				# .text:10105E36                 push    ecx
				# .text:10105E37                 xor     ecx, ecx
				# .text:10105E39                 lea     eax, [esp+1Ch]
				# .text:10105E3D                 call    sub_10077400
				# .text:10105E42                 mov     ecx, eax
				# .text:10105E44                 call    sub_1004EE50
				# .text:10105E49                 push    eax
				# .text:10105E4A                 call    sub_100D8EEE
				# .text:10105E4F                 push    ecx
				# .text:10105E50                 lea     edi, [esp+10h]
				# .text:10105E54                 fstp    qword ptr [esp]
				# .text:10105E57                 call    sub_1005B370
				# .text:10105E5C                 mov     eax, [esp+4] ; <----- insert hook here
				# .text:10105E60                 test    eax, eax
				# .text:10105E62                 mov     ecx, eax
				# .text:10105E64                 jz      short loc_10105E78
				
				call_count = 0 # hook after the 4th call, pretty lame but works fine for now.
				
				Metasm::Shellcode.disassemble( cpu, code ).decoded.each_value do | di |
					if( di.opcode.name.downcase == 'call' )
						call_count += 1
						next
					end
					if( not found and call_count == 4 ) 
						parsefloat += di.address
						patch_size += di.bin_length
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

				proxy = Metasm::Shellcode.assemble( cpu, %Q{
					pushfd
					pushad
					mov eax, [esp+0x0C+0x24] ; grab the pointer to the target object
					test eax, eax
					jz passthru_abort
					cmp dword [eax], 0x00000004 ; check it is the correct type
					jne passthru_abort
					mov eax, [eax+0x08] ; pull out the pointer to the data

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
				passthru_abort:
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

	Grinder::Core::Debugger.main( Grinder::Browser::Safari, ARGV )

end
