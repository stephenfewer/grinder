#
# Copyright (c) 2014, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
# Licensed under a 3 clause BSD license (Please see LICENSE.txt)
# Source code located at https://github.com/stephenfewer/grinder
#

require 'lib/metasm/metasm'
require 'core/logging'
require 'core/debug/processsymbols'
require 'core/debug/hookedprocess'
require 'core/debug/debuggerexception'
require 'core/debug/logger'
require 'core/debug/heaphook'

module Grinder

	module Core
	
		module Debug
		attr_accessor :trace_children
			class Debugger < ::Metasm::WinDebugger

				STATUS_STACK_BUFFER_OVERRUN = 0xC0000409 # /GS Exception
				STATUS_HEAP_CORRUPTION      = 0xC0000374 # /GS Exception
				CPP_EXCEPTION               = 0xE06D7363 # C++ EH exception
				
				include Grinder::Core::Debug::Logger
				
				include Grinder::Core::Debug::HeapHook

				def initialize( crashes_dir, target_exe, reduction, target_url, logdir=nil  )
					
					self.trace_children = true
					
					super( target_exe + ( extra_param ? ' ' + extra_param : '' ) + ' ' + target_url )
					
					@callback_newprocess = lambda do | info | 
					
						@attached[@pid] = Grinder::Core::Debug::HookedProcess.new( @pid, @os_process.handle, @os_process.addrsz )
						
						@attached[@pid].commandline = commandline()
					end
					
					@callback_unloadlibrary = lambda do | info |
						@attached[@pid].modules.delete( info[:address] ) if info[:address]
					end
					
					@callback_loadlibrary = lambda do | info |
					
						return if not info[:st].lpimagename
					
						name_ptr = @os_process.memory[info[:st].lpimagename, @os_process.addrsz / 8 ]
						
						return if not name_ptr
						
						name = @os_process.memory[ name_ptr.unpack( @os_process.addrsz == 64 ? 'Q' : 'V').first, 1024 ]
						
						if( info[:st].funicode == 1 )
							name = name.slice( 0..name.index("\x00\x00") ).unpack('S*').pack('C*')
						else
							name = name.slice( 0..name.index("\x00") )
						end
						
						@attached[@pid].modules[ info[:st].lpbaseofdll ] = name.downcase
					end
					
					@callback_newthread = lambda do | info | 
						self.handler_newthread()
					end
					
					if( $log_debug_messages )
						@callback_debugstring = lambda do | info | 
							debugstring = info ? info[:string] : nil
							if( debugstring and debugstring.force_encoding("UTF-8").ascii_only? and not debugstring.empty? )
								debugstring.chomp!
								@attached[@pid].debugstrings << debugstring
								print_status( "Debug message from process #{@pid}: #{debugstring}" )
							end
						end		
					end
					
					@callback_exception = lambda do | info | 
					
						@continuecode = ::Metasm::WinAPI::DBG_EXCEPTION_NOT_HANDLED
						
						return if not info
						
						if( info[:type] == 'breakpoint' )
							@continuecode = ::Metasm::WinAPI::DBG_CONTINUE
							return
						end
						
						self.handler_exception( info[:st] ? info[:st].exceptioncode : 0, info[:fault_access] )
					end	

					logger_initialize( logdir )
					
					heaphook_initialize()
					
					@browser     = ''
					@crashes_dir = crashes_dir
					@reduction   = reduction
					@attached    = ::Hash.new
					
					Grinder::Core::Debug::ProcessSymbols.init( extra_symbol_server() )
					
					print_status( "Running '#{target_exe}'" )
				end
				
				def extra_param
					return nil
				end
				
				def extra_symbol_server
					return nil
				end
				
				def get_dll_export( imagebase, name )
					pe = ::Metasm::LoadedPE.load( @os_process.memory[imagebase, 0x1000000] )
					pe.decode_header
					pe.decode_exports
					if pe.export
						pe.export.exports.each do |e|
							next if not rva = pe.label_rva( e.target )
							if( name == e.name )
								return imagebase + rva
							end
						end
					end
					return nil
				end
				
				def get_dll_imagebase( name )
					@attached[@pid].modules.each do | mod_base, mod_path |
						if( mod_path.include?( name ) )
							pe = ::Metasm::LoadedPE.load( @os_process.memory[mod_base, 0x100000] )
							pe.decode_header
							if( pe.header.machine == (@os_process.addrsz == 64 ? 'AMD64' : 'I386' ) )
								return mod_base
							end
						end
					end
					return nil
				end
				
				def encode_jmp( going_to, from_where, code_or_align=nil )
					asm = ''
					
					if( @os_process.addrsz == 64 )
						asm = "jmp [rip+0]\r\nfoo:dq #{ '0x%016X' % going_to }" # 14 bytes.
					else
						asm = "jmp $#{going_to < from_where ? '-' : '+'}#{[going_to, from_where].max-[going_to, from_where].min}"
					end
					
					cpu  = ::Metasm::Ia32.new( @os_process.addrsz )
					
					data = ::Metasm::Shellcode.assemble( cpu, asm ).encode_string
					
					if( code_or_align )
						aligned_size = 0
						
						if( code_or_align.class == ::Fixnum )
							aligned_size = code_or_align
						else
							::Metasm::Shellcode.disassemble( cpu, code_or_align ).decoded.each_value do | di |
								aligned_size += di.bin_length
								break if aligned_size >= data.length
							end
						end
						
						while( data.length < aligned_size )
							data << ::Metasm::Shellcode.assemble( cpu, "nop" ).encode_string
						end
					end
					
					return data
				end
				
				def commandline()

					wow64 = false
					if( ::Metasm::WinAPI.respond_to?( :iswow64process ) )
						byte = 0.chr*8
						if( ::Metasm::WinAPI.iswow64process( @os_process.handle, byte ) )
							wow64 = byte.unpack('V').first == 1 ? true : false
						end
					end

					# Note: a 32-bit wow64 process must have its command line read form its 64-bit PEB.
					
					if( @os_process.addrsz == 64 or wow64 )
						processparams = @os_process.memory[ @os_process.peb_base + 0x20, 8 ].unpack('Q').first
						return '' if not processparams

						len  = @os_process.memory[ processparams + 0x070,   2 ].unpack('v').first
						buff = @os_process.memory[ processparams + 0x070+8, 8 ].unpack('Q').first
						
						return '' if not buff or len == 0

						return @os_process.memory[ buff, len ].unpack('S*').pack('C*').gsub( "\x00", '' )
					else
						processparams = @os_process.memory[ @os_process.peb_base + 0x10, 4 ].unpack('V').first
						return '' if not processparams

						len  = @os_process.memory[ processparams + 0x040,   2 ].unpack('v').first
						buff = @os_process.memory[ processparams + 0x040+4, 4 ].unpack('V').first
						
						return '' if not buff or len == 0

						return @os_process.memory[ buff, len ].unpack('S*').pack('C*').gsub( "\x00", '' )
					end
				end

				# inject via the standard CreateRemoteThread/LoadLibrary technique...
				def inject_dll( library_name, pid )
					
					# we try to pull the kernel32 base address from our shadow module list
					# first, this is in case we have a 64bit ruby and a 32bit target process,  
					# in this instance LoadLibraryA would return the 64bit kernel32 address in 
					# our ruby vm and not the 32bit wow64 kernel address we want.
					
					hkernel = get_dll_imagebase( "kernel32.dll" )
					if( not hkernel )
						hkernel = ::Metasm::WinAPI.loadlibrarya( "kernel32.dll" )
					end
					
					return false if not hkernel
					
					loadlibrary_addr = get_dll_export( hkernel, "LoadLibraryA" )
					if( not loadlibrary_addr )	
						loadlibrary_addr = ::Metasm::WinAPI.getprocaddress( hkernel, "LoadLibraryA" )	
					end
					
					return false if not loadlibrary_addr
					
					# XXX: we could use WaitForInputIdle to ensure injection is safe but it deadlocks the ruby VM
					#Metasm::WinAPI.waitforinputidle( @os_process.handle, 10000 );	
					
					dll_addr = ::Metasm::WinAPI.virtualallocex( @os_process.handle, 0, library_name.length, ::Metasm::WinAPI::MEM_COMMIT|Metasm::WinAPI::MEM_RESERVE, ::Metasm::WinAPI::PAGE_READWRITE )
					
					return false if not dll_addr
					
					@os_process.memory[dll_addr, library_name.length] = library_name
					
					hinject = ::Metasm::WinAPI.createremotethread( @os_process.handle, 0, 0, loadlibrary_addr, dll_addr, 0, 0 )
					
					return false if not hinject
					
					# XXX: again we could use this to wait for the library to be loaded and get its base address, but it deadlocks the ruby VM :/
					#Metasm::WinAPI.waitforsingleobject( hinject, -1 )	

					return true
				end
				
				def handler_newthread()
					
					if( $instrument_heap and use_heaphook?( @pid ) and not @attached[@pid].heaphook_injected )
						@attached[@pid].heaphook_injected = inject_dll( @heaphook_dll, @pid )
						return
					end
					
					# we must inject grinder_logger.dll before grinder_heaphook.dll
					instrument_heap = $instrument_heap
					if( not @reduction and not @attached[@pid].logger_injected )
						instrument_heap = false
					end
	
					@attached[@pid].modules.each do | mod_base, mod_path |
							
						if( mod_path.include?( @heaphook_dll ) )
							
							if( instrument_heap and not @attached[@pid].heaphook_loaded )
								@attached[@pid].heaphook_loaded = heaphook_loader( mod_base )
							end
							
						elsif( mod_path.include?( 'vrfcore.dll' ) and not @attached[@pid].appverifier )
							
							print_warning( "Please note, Application Verifier is enabled for process #{@pid}." )
							
							@attached[@pid].appverifier = true
							
						elsif( @attached[@pid].heap_logmodule and not ( @configflags & CONFIG_PASSTHROUGH_STACK_WALK == CONFIG_PASSTHROUGH_STACK_WALK ) )
						
							@hhmodules.each_key do | hhmod |
								if( not @hhmodules[hhmod] and mod_path.include?( hhmod.downcase ) )
		
									hhmod_addr = ::Metasm::WinAPI.virtualallocex( @os_process.handle, 0, hhmod.length, ::Metasm::WinAPI::MEM_COMMIT|Metasm::WinAPI::MEM_RESERVE, ::Metasm::WinAPI::PAGE_READWRITE )
									
									@os_process.memory[hhmod_addr, hhmod.length] = hhmod

									::Metasm::WinAPI.createremotethread( @os_process.handle, 0, 0, @attached[@pid].heap_logmodule, hhmod_addr, 0, 0 )
									
									@hhmodules[hhmod] = true
								end
								
							end
						end
					end
	
					# if we are performing some form of testcase reduction we dont need to inject grinder_logger.dll
					if( not @reduction )

						if( use_logger?( @pid ) )
							#if( @attached.has_key?( @pid ) )
							if( not @attached[@pid].logger_injected )
								@attached[@pid].logger_injected = inject_dll( @logger_dll, @pid )
							end
							#end
							
							# Note: we dont rely on handler_loaddll() for dll load notification as we often dont recieve them all.
							# if everything is loaded for this process we do not itterate through this.
							if( not @attached[@pid].all_loaded or not @attached[@pid].logger_loaded )
								@attached[@pid].modules.each do | mod_base, mod_path |
									if( mod_path.include?( @logger_dll ) )
										if( not @attached[@pid].logger_loaded )
											@attached[@pid].logger_loaded = loader_logger( mod_base )
										end
									else 
										loaders( @pid, mod_path, mod_base )
									end
								end
							end
							
						end
						
					end
				end
				
				def handler_exception( exceptioncode, mode )

					if( exceptioncode == ::Metasm::WinAPI::STATUS_ACCESS_VIOLATION )
						data, hash, verified = log_exception()
						name = ''
						# see ExceptionInformation @ http://msdn.microsoft.com/en-us/library/windows/desktop/aa363082(v=vs.85).aspx
						if( mode == :r )
							name = 'Read '
						elsif( mode == :w )
							name = 'Write '
						elsif( mode == :x )
							name = 'Execute '
							verified = Grinder::Core::WebStats::VERIFIED_INTERESTING
						end
						name << 'Access Violation'
						raise Grinder::Core::Debug::DebuggerException.new( @browser, @crashes_dir, name, @pid, data, hash, verified )
					elsif( exceptioncode == STATUS_STACK_BUFFER_OVERRUN )
						data, hash, verified = log_exception()
						raise Grinder::Core::Debug::DebuggerException.new( @browser, @crashes_dir, 'Stack Buffer Overrun', @pid, data, hash, Grinder::Core::WebStats::VERIFIED_INTERESTING )
					elsif( exceptioncode == STATUS_HEAP_CORRUPTION )
						data, hash, verified = log_exception()
						raise Grinder::Core::Debug::DebuggerException.new( @browser, @crashes_dir, 'Heap Corruption', @pid, data, hash, Grinder::Core::WebStats::VERIFIED_INTERESTING )
					elsif( exceptioncode == ::Metasm::WinAPI::STATUS_ILLEGAL_INSTRUCTION )
						data, hash, verified = log_exception()
						raise Grinder::Core::Debug::DebuggerException.new( @browser, @crashes_dir, 'Illegal Instruction', @pid, data, hash, verified )
					elsif( exceptioncode == ::Metasm::WinAPI::STATUS_GUARD_PAGE_VIOLATION )
						data, hash, verified = log_exception()
						raise Grinder::Core::Debug::DebuggerException.new( @browser, @crashes_dir, 'Guard Page Violation', @pid, data, hash, verified )
					elsif( exceptioncode == ::Metasm::WinAPI::STATUS_NONCONTINUABLE_EXCEPTION )
						data, hash, verified = log_exception()
						raise Grinder::Core::Debug::DebuggerException.new( @browser, @crashes_dir, 'Noncontinuable Exception', @pid, data, hash, verified )
					elsif( exceptioncode == ::Metasm::WinAPI::STATUS_PRIVILEGED_INSTRUCTION )
						data, hash, verified = log_exception()
						raise Grinder::Core::Debug::DebuggerException.new( @browser, @crashes_dir, 'Privileged Instruction', @pid, data, hash, verified )
					elsif( exceptioncode == ::Metasm::WinAPI::STATUS_STACK_OVERFLOW )
						data, hash, verified = log_exception()
						raise Grinder::Core::Debug::DebuggerException.new( @browser, @crashes_dir, 'Stack Overflow', @pid, data, hash, verified )
					elsif( exceptioncode == ::Metasm::WinAPI::STATUS_INTEGER_DIVIDE_BY_ZERO )
						data, hash, verified = log_exception()
						raise Grinder::Core::Debug::DebuggerException.new( @browser, @crashes_dir, 'Divide By Zero', @pid, data, hash, verified )
					elsif( exceptioncode == ::Metasm::WinAPI::STATUS_IN_PAGE_ERROR )
						data, hash, verified = log_exception()
						name = ''
						if( mode == :r )
							name = 'Read '
						elsif( mode == :w )
							name = 'Write '
						elsif( mode == :x )
							name = 'Execute '
							verified = Grinder::Core::WebStats::VERIFIED_INTERESTING
						end
						name << 'Page Error'
						raise Grinder::Core::Debug::DebuggerException.new( @browser, @crashes_dir, name, @pid, data, hash, verified )
					elsif( exceptioncode == ::Metasm::WinAPI::STATUS_ARRAY_BOUNDS_EXCEEDED )
						data, hash, verified = log_exception()
						raise Grinder::Core::Debug::DebuggerException.new( @browser, @crashes_dir, 'Array Bounds Exceeded', @pid, data, hash, verified )
					elsif( exceptioncode == CPP_EXCEPTION )
						# XXX: we could pull out some extra info for logging, but for now we just ignore C++ EH exceptions.
					end

				end

				# Modified from METASM WinOS::Process.mappings (\metasm\os\windows.rb:899)
				def mem_prot( address )
					
					info = ::Metasm::WinAPI.alloc_c_struct( "MEMORY_BASIC_INFORMATION#{::Metasm::WinAPI.host_cpu.size}" )
					
					::Metasm::WinAPI.virtualqueryex( @os_process.handle, address, info, info.sizeof )
					
					if( (info[:state] & ::Metasm::WinAPI::MEM_COMMIT) > 0 )
						return {
							::Metasm::WinAPI::PAGE_NOACCESS          => '(---)',
							::Metasm::WinAPI::PAGE_READONLY          => '(R--)',
							::Metasm::WinAPI::PAGE_READWRITE         => '(RW-)',
							::Metasm::WinAPI::PAGE_WRITECOPY         => '(RW-)',
							::Metasm::WinAPI::PAGE_EXECUTE           => '(--X)',
							::Metasm::WinAPI::PAGE_EXECUTE_READ      => '(R-X)',
							::Metasm::WinAPI::PAGE_EXECUTE_READWRITE => '(RWX)',
							::Metasm::WinAPI::PAGE_EXECUTE_WRITECOPY => '(RWX)'
						}[ info[:protect] & 0xFF ]
					end
					
					'     '
				end

				def log_exception()

					verified   = Grinder::Core::WebStats::VERIFIED_UNKNOWN
					
					# seed the crash hashes first...
					hash_full  = ::Zlib.crc32( $hash_seed )
					hash_quick = ::Zlib.crc32( $hash_seed )

					ctx = @os_thread.context
					
					ctx.update

					#Metasm::WinAPI.debugactiveprocessstop( @pid )
					
					# Force all modules in the process to get their symbols for all upcoming lookups...
					@attached[@pid].refresh_symbols

					heaphook_parse_records
					
					resolve_sym = lambda do | address |
						sym = @attached[@pid].address2symbol( address )
						if( not sym.empty? )
							return " - #{sym}"
						end
						return ''
					end
					
					chunks = []
					
					resolve_chunk = lambda do | address |
						chunk = heaphook_find_chunk( address )
						if( chunk )
							if( chunks.include?( chunk ) )
								return " - Heap Chunk %d" % ( chunks.index( chunk ) + 1 )
							end
							chunks << chunk
							return " - Heap Chunk %d" % chunks.length
						end
						return ''
					end

					fmt       = ''
					sp        = 0
					bp        = 0
					registers = []
					
					if( @os_process.addrsz == 64 )	
						fmt       = '%016X'
						registers = [ 'Rax', 'Rbx', 'Rcx', 'Rdx', 'Rsi', 'Rdi', 'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15', 'Rbp', 'Rsp', 'Rip' ]
						ip        = ctx['Rip']
						sp        = ctx['Rsp']
						bp        = ctx['Rbp']
					else
						fmt       = '%08X'
						registers = [ 'Eax', 'Ebx', 'Ecx', 'Edx', 'Esi', 'Edi', 'Ebp', 'Esp', 'Eip' ]
						ip        = ctx['Eip']
						sp        = ctx['Esp']
						bp        = ctx['Ebp']
					end
					
					log_data  = "Registers:\n"
					
					registers.each do | reg |
						log_data << "    #{ '%-3s' % reg.downcase } = 0x#{ (fmt % ctx[reg]) } #{ mem_prot( ctx[reg] ) }#{ resolve_sym[ ctx[reg] ] }#{ resolve_chunk[ ctx[reg] ] }\n"
					end
					
					log_data << "\nCode:\n"
					
					prog = ::Metasm::ExeFormat.new( ::Metasm::Ia32.new( @os_process.addrsz ) )
						
					0.upto( 7 ) do
						data = @os_process.memory[ip,16]
						asm  = prog.cpu.decode_instruction( ::Metasm::EncodedData.new(data), ip )
						if( asm )
							assembly = asm.instruction.to_s.downcase
							
							# If its a CALL instruction, try to resolve the callee to a symbol name
							if( asm.opcode.name == 'call' and asm.instruction.args[0] and asm.instruction.args[0].respond_to?( :rexpr ) )
								calladdr = asm.instruction.args[0].rexpr
								if( calladdr )
									callsym = @attached[@pid].address2symbol( calladdr )
									if( not callsym.empty? )
										assembly = "call #{callsym}"
									end
								end
							end
							
							log_data << "    0x#{fmt % (ip)} - #{assembly}\n"
							
							ip += asm.bin_length
						else
							log_data << to_hex_dump( data, ip, 16, fmt )
							break
						end
					end
					
					# record the memory at the registers before we perform the stack walk
					# as the contents of ctx may be modified my the stackwalk api.
					memory_log_data = ''
					registers.each do | reg |
						next if mem_prot( ctx[reg] ).strip.empty?
						data = @os_process.memory[ ctx[reg], 128 ]
						if( data )
							memory_log_data << "Memory @ #{ '%s' % reg.downcase }:\n" << to_hex_dump( data, ctx[reg], 16, fmt )
						end
					end
					
					if( $old_debugger_stackwalk )
						# Note: the old debugger stack walking technique is available by setting the
						# global variable $old_debugger_stackwalk = true in your config.rb file.
						# The new method uses the DbgHelp StackWalk64 API and works on 32/64 bit threads,
						# while the old method only works on 32 bit threads.
						data = @os_process.memory[bp,(@os_process.addrsz / 8)*2]
						if( data )
							quick_count = 0
							log_data << "\nCall Stack:\n"
							0.upto( 64 ) do
								child_bp = data[0,(@os_process.addrsz / 8)].unpack( @os_process.addrsz == 64 ? 'Q' : 'V' ).first
								ret_addr = data[(@os_process.addrsz / 8),(@os_process.addrsz / 8)].unpack( @os_process.addrsz == 64 ? 'Q' : 'V' ).first
								break if( child_bp == 0 or ret_addr == 0 )
								ret_symbol = @attached[@pid].address2symbol( ret_addr )
								if( ret_symbol.empty? )
									# If we failed to lookup a symbol name, we can generate a pseudo symbol name via the module and the offset.
									# This avoids generating different crashes which if we had symbols, would all heve different crash hashes, but
									# due to a lack of symbols the different crashes end up being grouped together. This way we can better
									# differentiate them. However the main caveat of going this route is if a module changes due to an update,
									# the same crash may now generate a different crash hash (real symbols would avoid this). I still think
									# this is better then having a ton of different crashes with the same hash though. And IE, FF and CM have symbols.
									ret_symbol = @attached[@pid].address2moduleoffset( ret_addr )
									# if ret_addr wasnt belonging to any module (perhaps some jitted code in a virtualalloc'd block) then ret_symbol will be empty.
								end
								log_data << "    0x#{fmt % (ret_addr)} - #{ ret_symbol }\n"
								hash_full = ::Zlib.crc32( ret_symbol, hash_full )
								# we copy !exploitable in that we produce a hash from the first 5 symbols in the call stack to help identify similar bugs
								if( quick_count < 5 )
									hash_quick = ::Zlib.crc32( ret_symbol, hash_quick )
									quick_count += 1
								end
								data = @os_process.memory[child_bp,(@os_process.addrsz / 8)*2]
								break if not data
							end
						end
					else
						log_data << "\nCall Stack:\n"
						quick_count = 0
						frames      = @attached[@pid].stack_walk( @os_process.addrsz, @os_process.handle, @os_thread.handle, ctx, 64 )					
						frames.each do | ip |
							symbol = @attached[@pid].address2symbol( ip )
							if( symbol.empty? )
								# If we failed to lookup a symbol name, we can generate a pseudo symbol name via the module and the offset.
								# This avoids generating different crashes which if we had symbols, would all heve different crash hashes, but
								# due to a lack of symbols the different crashes end up being grouped together. This way we can better
								# differentiate them. However the main caveat of going this route is if a module changes due to an update,
								# the same crash may now generate a different crash hash (real symbols would avoid this). I still think
								# this is better then having a ton of different crashes with the same hash though. And IE, FF and CM have symbols.
								symbol = @attached[@pid].address2moduleoffset( ip )
								# if ip wasnt belonging to any module (perhaps some jitted code in a virtualalloc'd block) then ret_symbol will be empty.
							end
							
							log_data << "    0x#{fmt % ip} - #{ symbol }\n"
							
							hash_full = ::Zlib.crc32( symbol, hash_full )
							
							# we copy !exploitable in that we produce a hash from the first 5 symbols in the call stack to help identify similar bugs
							if( quick_count < 5 )
								hash_quick = ::Zlib.crc32( symbol, hash_quick )
								quick_count += 1
							end
						end
					end
					
					if( not chunks.empty? )
						log_data << "\nHeap Chunks:\n"
						index = 1
						
						chunks.each do | chunk |
							log_data << "    * Heap Chunk #{index}:\n"
							log_data << "          #{chunk.to_s}\n"
							chunk.callstack.each do | caller |
								log_data << "          #{caller}\n"
							end
							# XXX: do a hex dump
							log_data << "\n"
							index += 1
						end
						
						log_data << "\n"
					end
					
					if( not memory_log_data.empty? )
						log_data << "\n"
						log_data << memory_log_data
					end
										
					if( not @attached[@pid].debugstrings.empty? )
						log_data << "\nDebug Strings:\n"

						@attached[@pid].debugstrings.each do | debugstring |

							debugstring = debugstring.chomp
							
							debugstring = heaphook_parse_debugstring( debugstring )
							
							log_data << "    * #{debugstring}\n"
						end
						
						log_data << "\n"
					end
					
					if( not @attached[@pid].commandline.empty? )
						log_data << "Command Line:\n"
						log_data << "    #{@attached[@pid].commandline}\n"
						log_data << "\n"
					end
					
					log_data << "Modules:\n"
					
					@attached[@pid].modules.keys.sort.each do | mod_base |
						
						log_data << "    0x#{ fmt % (mod_base) } - #{ @attached[@pid].modules[mod_base] } "
						
						begin
							pe = ::Metasm::PE.decode_file_header( @attached[@pid].modules[mod_base] )
							
							version = pe.decode_version
							
							log_data << "- #{version['FileDescription']} " if version['FileDescription']
							log_data << "- #{version['FileVersion']} " if version['FileVersion']
						rescue
						end
						
						log_data << "\n"
					end
					
					hash = [ "#{ '%08X' % hash_quick }", "#{ '%08X' % hash_full }" ]
					
					return [ log_data, hash, verified ]
				end

				def monitor
					begin
						@attached[@pid] = Grinder::Core::Debug::HookedProcess.new( @pid, @os_process.handle, @os_process.addrsz )
						@attached[@pid].commandline = commandline()
						run_forever
					rescue Grinder::Core::Debug::DebuggerException => e
					
						# stop debugging this process!
						::Metasm::WinAPI.debugactiveprocessstop( e.pid )

						if( @reduction )
							e.set_testcase_crash
						else
							# log the crash to the console and optionally to the web
							log_data   = nil
							crash_data = e.save_crash()
							
							if( not crash_data )
								print_error( "Failed to save the crash file." )
							end
							
							if( use_logger?( e.pid ) )
							
								lfile = logger_file( e.pid )
								
								# If we don't have a log file for this PID, try to use the last modified log file.
								# This is a last ditch effort in case the crash occurred in a separate process
								# than the one being fuzzed. E.G. a Chrome GPU process crashes due to fuzzing in
								# the renderer. YMMV.
								if( not ::File.exists?( lfile ) )
									lfile = ::Dir.glob( gen_logger_filename( "*" ) ).max_by { | f | ::File.mtime( f ) }
								end
							
								log_data = e.save_log( lfile )
								
								if( not log_data )
									print_error( "Failed to save the log file." )
								end
							end

							e.log( crash_data, log_data )
						end
						detach
						return 1
					rescue ::Interrupt
						print_error( "Received an interrupt in main debugger loop." )
					end
					detach
					return 0
				end
				
				def self.main( klass, arguments )
					
					config_file = 'config'
					
					target_path = '/grinder'
					
					reduction   = false
					
					verbose     = true
					
					arguments.each do | arg |
						if( arg.include?( '--config=' ) )
							config_file = arg[9,arg.length]
						elsif( arg.include?( '--path=' ) )
							target_path = arg[7,arg.length]
						elsif( arg.include?( '--reduction' ) )
							reduction = true
						elsif( arg.include?( '--quiet' ) )
							verbose = false
						end
					end
					
					print_init( 'DEBUGGER', verbose, false )
					
					# As FireFox spits out a massive ammount of debug messages, we avoid logging
					# them unless the user has explicitly set the $log_debug_messages setting.
					# Note: we must do this before config_init() below.
					begin
						if( klass == Grinder::Browser::FireFox )
							eval( "$log_debug_messages = false" ) if $log_debug_messages == nil
						end
					rescue NameError
					end
					
					if( not config_init( config_file ) )
						print_error( "Failed to load the config file '#{config_file}'." )
						::Kernel::exit( false )
					end
							
					if( not config_test() )
						::Kernel::exit( false )
					end
					
					target_exe = klass.target_exe
					
					if( not ::File.exist?( target_exe ) )
						print_error( "File '#{target_exe}' does not exist, quitting." )
						::Kernel::exit( -1 )
					end

					print_status( "Starting at #{::Time.new.strftime( "%Y-%m-%d %H:%M:%S" )}" )
					
					if( not ::Metasm::WinOS.get_debug_privilege )
						print_error( "Failed to get debug privilege, quitting." )
						::Kernel::exit( -1 )
					end
										
					# Scan for any already running processes and fail as if we haven't spawned/debugged them all we can fail (As is the case with IE).
					exe_file = target_exe[ target_exe.rindex('\\')+1, target_exe.length-target_exe.rindex('\\') ]
					::Metasm::WinOS.list_processes.each do | proc |
						mods = proc.modules
						if( mods )
							if( mods.first and mods.first.path.include?( exe_file ) )
								# XXX: we should verify the process if for this current user and avoid killing another users instance.
								print_error( "Found an instance of #{exe_file} already running, killing..." )
								begin
									::Process.kill( "KILL", proc.pid )
									::Process.wait( proc.pid )
								rescue ::Errno::ESRCH, Errno::ECHILD
								end
								::Kernel::exit( -2 )
							end
						end
					end
					
					target_url = 'http://' + $server_address + ':' + $server_port.to_s + target_path
					
					begin
						debugger   = klass.new( $crashes_dir, target_exe, reduction, target_url, $logger_dir )

						status     = debugger.monitor
					rescue => e
						print_error( "Fatal error '#{e.message}', quitting." )
						print_simple( e.backtrace )
						status = -1
					end
					
					print_status( "Finished at #{::Time.new.strftime( "%Y-%m-%d %H:%M:%S" )}" )

					::Kernel::exit( status )

				end
				
			end
		
		end
		
	end
	
end