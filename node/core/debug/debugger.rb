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

module Grinder

	module Core
	
		module Debug
		
			class Debugger < Metasm::WinDbgAPI

				STATUS_STACK_BUFFER_OVERRUN = 0xC0000409 # /GS Exception
				
				def initialize( crashes_dir, target_exe, reduction, target_url, logdir=nil  )
					super( target_exe + ( extra_param ? ' ' + extra_param : '' ) + ' ' + target_url, true )
					@browser     = ''
					@crashes_dir = crashes_dir
					@reduction   = reduction
					@logger      = 'grinder_logger.dll'
					@logdir      = logdir ? logdir : ENV['TEMP']
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
				
				def inject_logger_dll( pid, rdi=false )
					if( rdi )
						# inject via Reflective DLL Injection...
						# read in the loader dll file...
						dll_data = ''
						::File.open( ".\\data\\#{@logger}", 'rb' ) do | f |
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
						dll_addr = Metasm::WinAPI.virtualallocex( @hprocess[pid], 0, @logger.length, Metasm::WinAPI::MEM_COMMIT|Metasm::WinAPI::MEM_RESERVE, Metasm::WinAPI::PAGE_READWRITE )
						return false if not dll_addr
						@mem[pid][dll_addr, @logger.length] = @logger
						hinject = Metasm::WinAPI.createremotethread( @hprocess[pid], 0, 0, loadlibrary_addr, dll_addr, 0, 0 )
						return false if not hinject
						# XXX: again we could use this to wait for the library to be loaded and get its base address, but it deadlocks the ruby VM :/
						#Metasm::WinAPI.waitforsingleobject( hinject, -1 )
						#dll_load_addr = 0
						#Metasm::WinAPI.getexitcodethread( hinject, dll_load_addr )
						#print_status( "Injected dll @ 0x#{'%08X' % (dll_load_addr)} into process '#{pid}'" )
					end
					return true
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
					
				def handler_newprocess( pid, tid, info )
					@attached[pid] = Grinder::Core::Debug::HookedProcess.new( pid, @hprocess[pid] )
					print_status( "Attached debugger to new process #{pid}" )
					
					super( pid, tid, info )
				end

				def handler_newthread( pid, tid, info )
					# if we are performing some form of testcase reduction we dont need to inject grinder_logger.dll
					if( not @reduction )
						if( @attached.has_key?( pid ) )
							if( not @attached[pid].logger_injected )
								@attached[pid].logger_injected = inject_logger_dll( pid )
							end
						end
						
						# Note: we dont rely on handler_loaddll() for dll load notification as we often dont recieve them all.
						#if everything is loaded for this process we do not itterate through this.
						if( not @attached[pid].all_loaded or not @attached[pid].logger_loaded )
							proc = Metasm::WinOS::Process.new( pid )
							proc.modules.each do | mod |
								if( mod.path.include?( 'grinder_logger' ) )
									if( not @attached[pid].logger_loaded )
										@attached[pid].logger_loaded = loader_logger( pid, mod.addr )
									end
								else 
									loaders( pid, mod.path, mod.addr )
								end
							end
						end
					end
					super( pid, tid, info )
				end
				

				def handler_debugstring( pid, tid, info )
					#info.ptr = @mem[pid][info.ptr, 4].unpack('L').first
					debugstring = @mem[pid][info.ptr, info.length]
					debugstring = debugstring.unpack('S*').pack('C*') if info.unicode != 0
					debugstring = debugstring[0, debugstring.index(?\0)] if debugstring.index(?\0)
					print_status( "Debug message from process #{pid}: #{debugstring}" )
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
				
				def logger_file( pid )
					"#{ @logdir }#{ @logdir.end_with?('\\') ? '' : '\\' }logger_#{ pid }.xml"
				end
				
				def loader_logger( pid, imagebase )
					print_status( "Logger DLL loaded into process #{pid} @ 0x#{'%08X' % imagebase }")
					
					setlogfile = get_dll_export( pid, imagebase, 'LOGGER_setLogFile' )
					if( setlogfile )
						file = logger_file( pid )
						file_addr = Metasm::WinAPI.virtualallocex( @hprocess[pid], 0, file.length, Metasm::WinAPI::MEM_COMMIT|Metasm::WinAPI::MEM_RESERVE, Metasm::WinAPI::PAGE_READWRITE )
						@mem[pid][file_addr, file.length] = file
						Metasm::WinAPI.createremotethread( @hprocess[pid], 0, 0, setlogfile, file_addr, 0, 0 )
						print_status( "Logging process #{pid} to log file '#{file}'" )
					else
						print_error( "Failed to resolved grinder_logger!LOGGER_setLogFile" )
					end
					
					if( not @attached[pid].logmessage )
						logmessage = get_dll_export( pid, imagebase, 'LOGGER_logMessage' )
						if( logmessage )
							@attached[pid].logmessage = logmessage
						else
							print_error( "Failed to resolved grinder_logger!LOGGER_logMessage" )
						end
					end
					
					if( not @attached[pid].finishedtest )
						finishedtest = get_dll_export( pid, imagebase, 'LOGGER_finishedTest' )
						if( finishedtest )
							@attached[pid].finishedtest = finishedtest
						else
							print_error( "Failed to resolved grinder_logger!LOGGER_finishedTest" )
						end
					end
					
					if( setlogfile and @attached[pid].logmessage and @attached[pid].finishedtest )
						return true
					end
					
					return false
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
					
					log_data  = "Registers:\n"
					log_data << "    EAX = 0x#{'%08X'%ctx[:eax]} - #{ mem_prot( pid, ctx[:eax] ) } - #{ @attached[pid].address2symbol( ctx[:eax], mods ) }\n"
					log_data << "    EBX = 0x#{'%08X'%ctx[:ebx]} - #{ mem_prot( pid, ctx[:ebx] ) } - #{ @attached[pid].address2symbol( ctx[:ebx], mods ) }\n"
					log_data << "    ECX = 0x#{'%08X'%ctx[:ecx]} - #{ mem_prot( pid, ctx[:ecx] ) } - #{ @attached[pid].address2symbol( ctx[:ecx], mods ) }\n"
					log_data << "    EDX = 0x#{'%08X'%ctx[:edx]} - #{ mem_prot( pid, ctx[:edx] ) } - #{ @attached[pid].address2symbol( ctx[:edx], mods ) }\n"
					log_data << "    ESI = 0x#{'%08X'%ctx[:esi]} - #{ mem_prot( pid, ctx[:esi] ) } - #{ @attached[pid].address2symbol( ctx[:esi], mods ) }\n"
					log_data << "    EDI = 0x#{'%08X'%ctx[:edi]} - #{ mem_prot( pid, ctx[:edi] ) } - #{ @attached[pid].address2symbol( ctx[:edi], mods ) }\n"
					log_data << "    EBP = 0x#{'%08X'%ctx[:ebp]} - #{ mem_prot( pid, ctx[:ebp] ) } - #{ @attached[pid].address2symbol( ctx[:ebp], mods ) }\n"
					log_data << "    ESP = 0x#{'%08X'%ctx[:esp]} - #{ mem_prot( pid, ctx[:esp] ) } - #{ @attached[pid].address2symbol( ctx[:esp], mods ) }\n"
					log_data << "    EIP = 0x#{'%08X'%ctx[:eip]} - #{ mem_prot( pid, ctx[:eip] ) } - #{ @attached[pid].address2symbol( ctx[:eip], mods ) }\n"

					offset = ctx[:eip]
					prog = Metasm::ExeFormat.new( Metasm::Ia32.new )
					log_data << "Code:\n"
					0.upto( 7 ) do
						data = @mem[pid][offset,16]
						asm  = prog.cpu.decode_instruction( Metasm::EncodedData.new(data), offset )
						if( asm )
							assembly = asm.instruction.to_s.upcase
							
							# If its a CALL instruction, try to resolve the callee to a symbol name
							if( asm.opcode.name.downcase == 'call' )
								calladdr = asm.instruction.args[0].rexpr
								if( calladdr )
									callsym = @attached[pid].address2symbol( calladdr, mods )
									if( not callsym.empty? )
										assembly = "CALL #{callsym}"
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
						log_data << "Stack:\n" << to_hex_dump( data, ctx[:esp] )
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
						end
						
						#if( not @reduction or ( @reduction and not e.duplicate? ) )
						if( not @reduction )
							# log the crash to the console and optionally to the web
							
							crash_data = e.save_crash()
							log_data   = e.save_log( logger_file( e.pid ) )
							
							if( not crash_data )
								print_error( "Failed to save the crash file." )
							end
							
							if( not log_data )
								print_error( "Failed to save the log file." )
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
								print_error( "Found an instance of #{exe_file} already running, quiting." )
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