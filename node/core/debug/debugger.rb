#
# Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
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
		
			class Debugger < Metasm::WinDbgAPI

				STATUS_STACK_BUFFER_OVERRUN = 0xC0000409 # /GS Exception
				STATUS_HEAP_CORRUPTION      = 0xC0000374 # /GS Exception
				
				include Grinder::Core::Debug::Logger
				
				include Grinder::Core::Debug::HeapHook
				
				def initialize( crashes_dir, target_exe, reduction, target_url, logdir=nil  )
					
					super( target_exe + ( extra_param ? ' ' + extra_param : '' ) + ' ' + target_url, true )
					
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
				
				def get_dll_export( pid, imagebase, name )
					pe = Metasm::LoadedPE.load( @mem[pid][imagebase, 0x1000000] )
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

				def jmp5( going_to, from_where )
					Metasm::Shellcode.assemble( Metasm::Ia32.new, "jmp $#{going_to < from_where ? '-' : '+'}#{[going_to, from_where].max-[going_to, from_where].min}" ).encode_string
				end
				
				def commandline( pid, info )
					peb = @mem[pid][ info.threadlocalbase + 0x30, 4 ].unpack('V').first
					return '' if not peb

					processparams = @mem[pid][ peb + 0x10, 4 ].unpack('V').first
					return '' if not processparams

					len, max, buff = @mem[pid][ processparams + 0x40, 8 ].unpack('vvV')
					return '' if not buff or len == 0
					
					return @mem[pid][ buff, len ].unpack('S*').pack('C*').gsub( "\x00", '' )
				end
				
				def handler_newprocess( pid, tid, info )
					@attached[pid] = Grinder::Core::Debug::HookedProcess.new( pid, @hprocess[pid] )
					
					@attached[pid].commandline = commandline( pid, info )
					
					print_status( "Attached debugger to new process #{pid}" )

					super( pid, tid, info )
				end

				def inject_dll( library_name, pid, rdi=false )
					if( rdi )
						# inject via Reflective DLL Injection...
						# read in the loader dll file...
						dll_data = ''
						::File.open( ".\\data\\#{library_name}", 'rb' ) do | f |
							dll_data << f.read( f.stat.size )
						end
						# alloc some space in host process for the dll
						dll_addr = Metasm::WinAPI.virtualallocex( @hprocess[pid], 0, dll_data.length, Metasm::WinAPI::MEM_COMMIT|Metasm::WinAPI::MEM_RESERVE, Metasm::WinAPI::PAGE_EXECUTE_READWRITE )
						return false if not dll_addr
						# write the dll file into the host process
						@mem[pid][dll_addr, dll_data.length] = dll_data
						# get the file offset to the ReflectiveLoader function
						reflectiveloader = nil
						pe = Metasm::PE.decode( dll_data )
						if pe.export
							pe.export.exports.each do |e|
								next if not rva = pe.label_rva( e.target )
								if( e.name == '_ReflectiveLoader@4' )
									if( s = pe.sect_at_rva( rva ) )
										reflectiveloader = dll_addr + ( rva - s.virtaddr + s.rawaddr )
										break
									end
								end
							end
						end
						return false if not reflectiveloader
						# and execute the ReflectiveLoader
						hinject = Metasm::WinAPI.createremotethread( @hprocess[pid], 0, 0, reflectiveloader, 0, 0, 0 )
						return false if not hinject
					else
						# inject via the standard CreateRemoteThread/LoadLibrary technique...
						hkernel = Metasm::WinAPI.loadlibrarya( "kernel32.dll" )
						return false if not hkernel
						loadlibrary_addr = Metasm::WinAPI.getprocaddress( hkernel, "LoadLibraryA" )	
						return false if not loadlibrary_addr
						# XXX: we could use WaitForInputIdle to ensure injection is safe but it deadlocks the ruby VM
						#Metasm::WinAPI.waitforinputidle( @hprocess[pid], 10000 );	
						dll_addr = Metasm::WinAPI.virtualallocex( @hprocess[pid], 0, library_name.length, Metasm::WinAPI::MEM_COMMIT|Metasm::WinAPI::MEM_RESERVE, Metasm::WinAPI::PAGE_READWRITE )
						return false if not dll_addr
						@mem[pid][dll_addr, library_name.length] = library_name
						hinject = Metasm::WinAPI.createremotethread( @hprocess[pid], 0, 0, loadlibrary_addr, dll_addr, 0, 0 )
						return false if not hinject
						# XXX: again we could use this to wait for the library to be loaded and get its base address, but it deadlocks the ruby VM :/
						#Metasm::WinAPI.waitforsingleobject( hinject, -1 )	
					end
					return true
				end
				
				def handler_newthread( pid, tid, info )
					
					if( $instrument_heap and use_heaphook?( pid ) and not @attached[pid].heaphook_injected )
						@attached[pid].heaphook_injected = inject_dll( @heaphook_dll, pid )
						return super( pid, tid, info )
					end
					
					proc = Metasm::WinOS::Process.new( pid )
	
					# we must inject grinder_logger.dll before grinder_heaphook.dll
					instrument_heap = $instrument_heap
					if( not @reduction and not @attached[pid].logger_injected )
						instrument_heap = false
					end
	
					proc.modules.each do | mod |
							
						if( mod.path.downcase.include?( @heaphook_dll ) )
							
							if( instrument_heap and not @attached[pid].heaphook_loaded )
								@attached[pid].heaphook_loaded = heaphook_loader( pid, mod.addr )
							end
							
						elsif( mod.path.downcase.include?( 'vrfcore.dll' ) and not @attached[pid].appverifier )
							
							print_warning( "Please note, Application Verifier is enabled for process #{pid}" )
							
							@attached[pid].appverifier = true
							
						elsif( @attached[pid].heap_logmodule and not ( @configflags & CONFIG_PASSTHROUGH_STACK_WALK == CONFIG_PASSTHROUGH_STACK_WALK ) )
						
							@hhmodules.each_key do | hhmod |
								if( not @hhmodules[hhmod] and mod.path.downcase.include?( hhmod.downcase ) )
		
									hhmod_addr = Metasm::WinAPI.virtualallocex( @hprocess[pid], 0, hhmod.length, Metasm::WinAPI::MEM_COMMIT|Metasm::WinAPI::MEM_RESERVE, Metasm::WinAPI::PAGE_READWRITE )
									
									@mem[pid][hhmod_addr, hhmod.length] = hhmod

									Metasm::WinAPI.createremotethread( @hprocess[pid], 0, 0, @attached[pid].heap_logmodule, hhmod_addr, 0, 0 )
									
									@hhmodules[hhmod] = true
								end
								
							end
						end
					end
	
					# if we are performing some form of testcase reduction we dont need to inject grinder_logger.dll
					if( not @reduction )

						if( use_logger?( pid ) )
						
							#if( @attached.has_key?( pid ) )
							if( not @attached[pid].logger_injected )
								@attached[pid].logger_injected = inject_dll( @logger, pid )
							end
							#end
							
							# Note: we dont rely on handler_loaddll() for dll load notification as we often dont recieve them all.
							# if everything is loaded for this process we do not itterate through this.
							if( not @attached[pid].all_loaded or not @attached[pid].logger_loaded )
								proc.modules.each do | mod |
									if( mod.path.downcase.include?( @logger ) )
										if( not @attached[pid].logger_loaded )
											@attached[pid].logger_loaded = loader_logger( pid, mod.addr )
										end
									else 
										loaders( pid, mod.path.downcase, mod.addr )
									end
								end
							end
							
						end
						
					end
					
					super( pid, tid, info )
				end

				def handler_debugstring( pid, tid, info )

					debugstring = @mem[pid][info.ptr, info.length].unpack( info.unicode == 0 ? 'C*' : 'v*' )

					debugstring = debugstring.pack('C*') rescue debugstring.pack('v*')
				
					if( debugstring.force_encoding("UTF-8").ascii_only? and not debugstring.empty? )
						@attached[pid].debugstrings << debugstring
						print_status( "Debug message from process #{pid}: #{debugstring}" )
					end
					
					Metasm::WinAPI::DBG_CONTINUE
				end
				
				def handler_exception( pid, tid, info )

					if( info.code == Metasm::WinAPI::STATUS_ACCESS_VIOLATION )
					
						#if( info.recordptr != 0 )
							#typedef struct _EXCEPTION_RECORD32 {
							#	DWORD ExceptionCode;
							#	DWORD ExceptionFlags;
							#	DWORD ExceptionRecord;
							#	DWORD ExceptionAddress;
							#	DWORD NumberParameters;
							#	DWORD ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
							#} EXCEPTION_RECORD32, *PEXCEPTION_RECORD32;
							#exceptionrecord = @mem[pid][info.recordptr,20]
							#exceptioncode   = exceptionrecord[0,4].unpack('L').first
							#p "exceptioncode = 0x#{'%08X' % exceptioncode }"
						#end
					
						data, hash, verified = log( pid, tid )
						name = 'Access Violation'
						# see ExceptionInformation @ http://msdn.microsoft.com/en-us/library/windows/desktop/aa363082(v=vs.85).aspx
						if( info.nparam >= 1 )
							type = info.info[0]
							if( type == 0 )
								name = 'Read Access Violation'
							elsif( type == 1 )
								name = 'Write Access Violation'
							elsif( type == 8 )
								name = 'Execute Access Violation'
								verified = Grinder::Core::WebStats::VERIFIED_INTERESTING
							end
						end
						raise Grinder::Core::Debug::DebuggerException.new( @browser, @crashes_dir, name, pid, data, hash, verified )
					elsif( info.code == STATUS_STACK_BUFFER_OVERRUN )
						data, hash, verified = log( pid, tid )
						raise Grinder::Core::Debug::DebuggerException.new( @browser, @crashes_dir, 'Stack Buffer Overrun', pid, data, hash, Grinder::Core::WebStats::VERIFIED_INTERESTING )
					elsif( info.code == STATUS_HEAP_CORRUPTION )
						data, hash, verified = log( pid, tid )
						raise Grinder::Core::Debug::DebuggerException.new( @browser, @crashes_dir, 'Heap Corruption', pid, data, hash, Grinder::Core::WebStats::VERIFIED_INTERESTING )
					elsif( info.code == Metasm::WinAPI::STATUS_ILLEGAL_INSTRUCTION )
						data, hash, verified = log( pid, tid )
						raise Grinder::Core::Debug::DebuggerException.new( @browser, @crashes_dir, 'Illegal Instruction', pid, data, hash, verified )
					elsif( info.code == Metasm::WinAPI::STATUS_GUARD_PAGE_VIOLATION )
						data, hash, verified = log( pid, tid )
						raise Grinder::Core::Debug::DebuggerException.new( @browser, @crashes_dir, 'Guard Page Violation', pid, data, hash, verified )
					elsif( info.code == Metasm::WinAPI::STATUS_NONCONTINUABLE_EXCEPTION )
						data, hash, verified = log( pid, tid )
						raise Grinder::Core::Debug::DebuggerException.new( @browser, @crashes_dir, 'Noncontinuable Exception', pid, data, hash, verified )
					elsif( info.code == Metasm::WinAPI::STATUS_PRIVILEGED_INSTRUCTION )
						data, hash, verified = log( pid, tid )
						raise Grinder::Core::Debug::DebuggerException.new( @browser, @crashes_dir, 'Privileged Instruction', pid, data, hash, verified )
					elsif( info.code == Metasm::WinAPI::STATUS_STACK_OVERFLOW )
						data, hash, verified = log( pid, tid )
						raise Grinder::Core::Debug::DebuggerException.new( @browser, @crashes_dir, 'Stack Overflow', pid, data, hash, verified )
					elsif( info.code == Metasm::WinAPI::STATUS_INTEGER_DIVIDE_BY_ZERO )
						data, hash, verified = log( pid, tid )
						raise Grinder::Core::Debug::DebuggerException.new( @browser, @crashes_dir, 'Divide By Zero', pid, data, hash, verified )
					elsif( info.code == Metasm::WinAPI::STATUS_IN_PAGE_ERROR )
						data, hash, verified = log( pid, tid )
						name = 'Page Error'
						if( info.nparam >= 1 )
							type = info.info[0]
							if( type == 0 )
								name = 'Read Page Error'
							elsif( type == 1 )
								name = 'Write Page Error'
							elsif( type == 8 )
								name = 'Execute Page Error'
								verified = Grinder::Core::WebStats::VERIFIED_INTERESTING
							end
						end
						raise Grinder::Core::Debug::DebuggerException.new( @browser, @crashes_dir, name, pid, data, hash, verified )
					elsif( info.code == Metasm::WinAPI::STATUS_ARRAY_BOUNDS_EXCEEDED )
						data, hash, verified = log( pid, tid )
						raise Grinder::Core::Debug::DebuggerException.new( @browser, @crashes_dir, 'Array Bounds Exceeded', pid, data, hash, verified )
					end
					
					super( pid, tid, info )
				end

				# Modified from METASM WinOS::Process.mappings (\metasm\os\windows.rb:899)
				def mem_prot( pid, address )
					info = Metasm::WinAPI.alloc_c_struct( "MEMORY_BASIC_INFORMATION32" )
					Metasm::WinAPI.virtualqueryex( @hprocess[pid], address, info, info.length )
					if( info[:state] & Metasm::WinAPI::MEM_COMMIT > 0 )
						return {
							Metasm::WinAPI::PAGE_NOACCESS          => '---',
							Metasm::WinAPI::PAGE_READONLY          => 'R--',
							Metasm::WinAPI::PAGE_READWRITE         => 'RW-',
							Metasm::WinAPI::PAGE_WRITECOPY         => 'RW-',
							Metasm::WinAPI::PAGE_EXECUTE           => '--X',
							Metasm::WinAPI::PAGE_EXECUTE_READ      => 'R-X',
							Metasm::WinAPI::PAGE_EXECUTE_READWRITE => 'RWX',
							Metasm::WinAPI::PAGE_EXECUTE_WRITECOPY => 'RWX'
						}[ info[:protect] & 0xFF ]
					end
					'   '
				end

				def log( pid, tid )

					verified = Grinder::Core::WebStats::VERIFIED_UNKNOWN
					
					# seed the crash hashes first...
					hash_full  = ::Zlib.crc32( $hash_seed )
					hash_quick = ::Zlib.crc32( $hash_seed )
					
					ctx = get_context( pid, tid )		

					#Metasm::WinAPI.debugactiveprocessstop( pid )
					
					# Force all moduels in the process to get their symbols for all upcoming lookups...
					@attached[pid].refresh_symbols
					
					proc = Metasm::WinOS::Process.new( pid )
					
					mods = proc.modules.sort_by do | mod |
						mod.addr
					end

					heaphook_parse_records( pid, mods )
					
					resolve_sym = lambda do | address |
						sym = @attached[pid].address2symbol( address, mods )
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
					
					log_data  = "Registers:\n"
					log_data << "    EAX = 0x#{'%08X'%ctx[:eax]} - #{ mem_prot( pid, ctx[:eax] ) }#{ resolve_sym.call( ctx[:eax] ) }#{ resolve_chunk.call( ctx[:eax] ) }\n"
					log_data << "    EBX = 0x#{'%08X'%ctx[:ebx]} - #{ mem_prot( pid, ctx[:ebx] ) }#{ resolve_sym.call( ctx[:ebx] ) }#{ resolve_chunk.call( ctx[:ebx] ) }\n"
					log_data << "    ECX = 0x#{'%08X'%ctx[:ecx]} - #{ mem_prot( pid, ctx[:ecx] ) }#{ resolve_sym.call( ctx[:ecx] ) }#{ resolve_chunk.call( ctx[:ecx] ) }\n"
					log_data << "    EDX = 0x#{'%08X'%ctx[:edx]} - #{ mem_prot( pid, ctx[:edx] ) }#{ resolve_sym.call( ctx[:edx] ) }#{ resolve_chunk.call( ctx[:edx] ) }\n"
					log_data << "    ESI = 0x#{'%08X'%ctx[:esi]} - #{ mem_prot( pid, ctx[:esi] ) }#{ resolve_sym.call( ctx[:esi] ) }#{ resolve_chunk.call( ctx[:esi] ) }\n"
					log_data << "    EDI = 0x#{'%08X'%ctx[:edi]} - #{ mem_prot( pid, ctx[:edi] ) }#{ resolve_sym.call( ctx[:edi] ) }#{ resolve_chunk.call( ctx[:edi] ) }\n"
					log_data << "    EBP = 0x#{'%08X'%ctx[:ebp]} - #{ mem_prot( pid, ctx[:ebp] ) }#{ resolve_sym.call( ctx[:ebp] ) }#{ resolve_chunk.call( ctx[:ebp] ) }\n"
					log_data << "    ESP = 0x#{'%08X'%ctx[:esp]} - #{ mem_prot( pid, ctx[:esp] ) }#{ resolve_sym.call( ctx[:esp] ) }#{ resolve_chunk.call( ctx[:esp] ) }\n"
					log_data << "    EIP = 0x#{'%08X'%ctx[:eip]} - #{ mem_prot( pid, ctx[:eip] ) }#{ resolve_sym.call( ctx[:eip] ) }#{ resolve_chunk.call( ctx[:eip] ) }\n"

					offset = ctx[:eip]
					
					prog = Metasm::ExeFormat.new( Metasm::Ia32.new )
					
					log_data << "\nCode:\n"
					
					0.upto( 7 ) do
						data = @mem[pid][offset,16]
						asm  = prog.cpu.decode_instruction( Metasm::EncodedData.new(data), offset )
						if( asm )
							assembly = asm.instruction.to_s.downcase
							
							# If its a CALL instruction, try to resolve the callee to a symbol name
							if( asm.opcode.name == 'call' and asm.instruction.args[0] and asm.instruction.args[0].respond_to?( :rexpr ) )
								calladdr = asm.instruction.args[0].rexpr
								if( calladdr )
									callsym = @attached[pid].address2symbol( calladdr, mods )
									if( not callsym.empty? )
										assembly = "call #{callsym}"
									end
								end
							end
							
							log_data << "    0x#{'%08X' % (offset)} - #{assembly}\n"
							
							offset += asm.bin_length
						else
							log_data << to_hex_dump( data, offset )
							break
						end
					end
					
					data = @mem[pid][ctx[:esp],128]
					if( data )
						log_data << "\nStack:\n" << to_hex_dump( data, ctx[:esp] )
					end
					
					quick_count = 0
					
					data = @mem[pid][ctx[:ebp],8]
					if( data )
						log_data << "Call Stack:\n"
						0.upto( 64 ) do
							child_ebp = data[0,4].unpack('V').first
							ret_addr  = data[4,4].unpack('V').first
							break if( child_ebp == 0 or ret_addr == 0 )
							ret_symbol = @attached[pid].address2symbol( ret_addr, mods )
							if( ret_symbol.empty? )
								# If we failed to lookup a symbol name, we can generate a pseudo symbol name via the module and the offset.
								# This avoids generating different crashes which if we had symbols, would all heve different crash hashes, but
								# due to a lack of symbols the different crashes end up being grouped together. This way we can better
								# differentiate them. However the main caveat of going this route is if a module changes due to an update,
								# the same crash may now generate a different crash hash (real symbols would avoid this). I still think
								# this is better then having a ton of different crashes with the same hash though. And IE, FF and CM have symbols.
								ret_symbol = @attached[pid].address2moduleoffset( ret_addr, mods )
								# if ret_addr wasnt belonging to any module (perhaps some jitted code in a virtualalloc'd block) then ret_symbol will be empty.
							end
							log_data << "    0x#{'%08X' % (ret_addr)} - #{ ret_symbol }\n"
							hash_full = ::Zlib.crc32( ret_symbol, hash_full )
							# we copy !exploitable in that we produce a hash from the first 5 symbols in the call stack to help identify similar bugs
							if( quick_count < 5 )
								hash_quick = ::Zlib.crc32( ret_symbol, hash_quick )
								quick_count += 1
							end
							data = @mem[pid][child_ebp,8]
							break if not data
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
						
					if( not @attached[pid].debugstrings.empty? )
						log_data << "\nDebug Strings:\n"

						@attached[pid].debugstrings.each do | debugstring |

							debugstring = debugstring.chomp
							
							debugstring = heaphook_parse_debugstring( debugstring, pid, mods )
							
							log_data << "    * #{debugstring}\n"
						end
						
						log_data << "\n"
					end
					
					if( not @attached[pid].commandline.empty? )
						log_data << "Command Line:\n"
						log_data << "    #{@attached[pid].commandline}\n"
						log_data << "\n"
					end
					
					log_data << "Modules:\n"
					mods.each do | mod |
						
						log_data << "    0x#{'%08X' % (mod.addr)} - #{mod.path.downcase} "
						
						begin
							pe = Metasm::PE.decode_file_header( mod.path )
							
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

				#def kill
				#	@attached.each do | proc |
				#		#Metasm::WinAPI.debugactiveprocessstop( pid )
				#		Metasm::WinAPI.terminateprocess( proc[0], 0 )
				#	end
				#end
				
				def monitor
					begin
						loop
					rescue Grinder::Core::Debug::DebuggerException => e
						# stop debugging this process!
						Metasm::WinAPI.debugactiveprocessstop( e.pid )

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
							
								log_data = e.save_log( logger_file( e.pid ) )
								
								if( not log_data )
									print_error( "Failed to save the log file." )
								end
							end

							e.log( crash_data, log_data )
						end

						return 1
					rescue ::Interrupt
						print_error( "Received an interrupt in main debugger loop." )
					end
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
					
					if( not config_init( config_file ) )
						print_error( "Failed to load the config file '#{config_file}'." )
						::Kernel::exit( false )
					end
							
					if( not config_test() )
						::Kernel::exit( false )
					end
					
					print_init( 'DEBUGGER', verbose, false )

					print_status( "Starting at #{::Time.new.strftime( "%Y-%m-%d %H:%M:%S" )}" )
					
					if( not Metasm::WinOS.get_debug_privilege )
						print_error( "Failed to get debug privilege, quiting." )
						::Kernel::exit( -1 )
					end
					
					target_exe = klass.target_exe

					# Scan for any already running processes and fail as if we havent spawned/debugged them all we can fail (As is the case with IE).
					exe_file = target_exe[ target_exe.rindex('\\')+1, target_exe.length-target_exe.rindex('\\') ]
					Metasm::WinOS.list_processes.each do | proc |
						mods = proc.modules
						if( mods )
							if( mods.first and mods.first.path.include?( exe_file ) )
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
					
					debugger   = klass.new( $crashes_dir, target_exe, reduction, target_url, $logger_dir )

					status     = debugger.monitor

					print_status( "Finished at #{::Time.new.strftime( "%Y-%m-%d %H:%M:%S" )}" )

					::Kernel::exit( status )

				end
				
			end
		
		end
		
	end
	
end