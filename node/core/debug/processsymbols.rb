#
# Copyright (c) 2014, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
# Licensed under a 3 clause BSD license (Please see LICENSE.txt)
# Source code located at https://github.com/stephenfewer/grinder
#

require 'lib/metasm/metasm'
require 'core/logging'

module Grinder

	module Core
	
		module Debug
		
			# http://msdn.microsoft.com/en-us/library/ms681366%28v=vs.85%29.aspx
			SYMOPT_CASE_INSENSITIVE      = 0x00000001
			SYMOPT_UNDNAME               = 0x00000002
			SYMOPT_DEFERRED_LOADS        = 0x00000004
			SYMOPT_DEBUG                 = 0x80000000
			SYMOPT_LOAD_LINES            = 0x00000010
			SYMOPT_NO_PROMPTS            = 0x00080000
			SYMOPT_INCLUDE_32BIT_MODULES = 0x00002000
			
			DBGHELP_PATH                 = ".\\data\\#{ ::Metasm::WinAPI.host_cpu.size == 64 ? 'x64' : 'x86' }\\dbghelp.dll"
			SYMSRV_PATH                  = ".\\data\\#{ ::Metasm::WinAPI.host_cpu.size == 64 ? 'x64' : 'x86' }\\symsrv.dll"
			PSAPI_PATH                   = "psapi.dll"
			
			PUBLIC_SYMBOL_SERVER         = "http://msdl.microsoft.com/download/symbols"
			
			IMAGE_FILE_MACHINE_I386      = 0x014C
			IMAGE_FILE_MACHINE_AMD64     = 0x8664
			
			::Metasm::WinAPI.new_api_c( 'WINBASEAPI HMODULE WINAPI LoadLibraryA( __in LPCSTR lpLibFileName );', 'kernel32' )
			::Metasm::WinAPI.new_api_c( 'WINBASEAPI LPVOID WINAPI GetProcAddress( __in HMODULE hModule, __in LPCSTR lpProcName );', 'kernel32' )
			::Metasm::WinAPI.new_api_c( 'WINBASEAPI DWORD WINAPI WaitForSingleObject( __in HANDLE hHandle, __in DWORD dwMilliseconds );', 'kernel32' )

			::Metasm::WinAPI.new_api_c( 'WINUSERAPI DWORD WINAPI WaitForInputIdle( __in HANDLE hProcess, __in DWORD dwMilliseconds );', 'user32' )

			::Metasm::WinAPI.new_api_c( 'typedef struct _SYMBOL_INFO {
				ULONG   SizeOfStruct;
				ULONG   TypeIndex;
				DWORD64 Reserved1;
				DWORD64 Reserved2;
				ULONG   Index;
				ULONG   Size;
				DWORD64 ModBase;
				ULONG   Flags;
				DWORD64 Value;
				DWORD64 Address;
				ULONG   Register;
				ULONG   Scope;
				ULONG   Tag;
				ULONG   NameLen;
				ULONG   MaxNameLen;
				CHAR    Name[512];
			} SYMBOL_INFO, *LPSYMBOL_INFO;', DBGHELP_PATH )
			
			::Metasm::WinAPI.new_api_c( 'typedef enum { 
				AddrMode1616, AddrMode1632, AddrModeReal, AddrModeFlat
			} ADDRESS_MODE;', DBGHELP_PATH )
			
			::Metasm::WinAPI.new_api_c( 'typedef struct _tagADDRESS64 {
				DWORD64      Offset;
				WORD         Segment;
				ADDRESS_MODE Mode;
			} ADDRESS64, *LPADDRESS64;', DBGHELP_PATH )
			
			::Metasm::WinAPI.new_api_c( 'typedef struct _KDHELP64 {
				DWORD64 Thread;
				DWORD   ThCallbackStack;
				DWORD   ThCallbackBStore;
				DWORD   NextCallback;
				DWORD   FramePointer;
				DWORD64 KiCallUserMode;
				DWORD64 KeUserCallbackDispatcher;
				DWORD64 SystemRangeStart;
				DWORD64 KiUserExceptionDispatcher;
				DWORD64 StackBase;
				DWORD64 StackLimit;
				DWORD64 Reserved[5];
			} KDHELP64, *PKDHELP64;', DBGHELP_PATH )

			::Metasm::WinAPI.new_api_c( 'typedef struct _tagSTACKFRAME64 {
				ADDRESS64 AddrPC;
				ADDRESS64 AddrReturn;
				ADDRESS64 AddrFrame;
				ADDRESS64 AddrStack;
				ADDRESS64 AddrBStore;
				PVOID     FuncTableEntry;
				DWORD64   Params[4];
				BOOL      Far;
				BOOL      Virtual;
				DWORD64   Reserved[3];
				KDHELP64  KdHelp;
			} STACKFRAME64, *LPSTACKFRAME64;', DBGHELP_PATH )

			::Metasm::WinAPI.new_api_c( 'WINUSERAPI BOOL WINAPI StackWalk64(
				__in DWORD MachineType,
				__in HANDLE hProcess,
				__in HANDLE hThread,
				__inout LPSTACKFRAME64 StackFrame,
				__inout PVOID ContextRecord,
				__in PVOID ReadMemoryRoutine,
				__in PVOID FunctionTableAccessRoutine,
				__in PVOID GetModuleBaseRoutine,
				__in PVOID TranslateAddress
			);', DBGHELP_PATH )
			
			::Metasm::WinAPI.new_api_c( 'WINUSERAPI PVOID WINAPI SymFunctionTableAccess64(
				__in HANDLE hProcess,
				__in DWORD64 AddrBase
			);', DBGHELP_PATH )
			
			::Metasm::WinAPI.new_api_c( 'WINUSERAPI DWORD64 WINAPI SymGetModuleBase64(
				__in HANDLE hProcess,
				__in DWORD64 dwAddr
			);', DBGHELP_PATH )
			
			::Metasm::WinAPI.new_api_c( 'WINUSERAPI DWORD WINAPI SymGetOptions( VOID );', DBGHELP_PATH )
			::Metasm::WinAPI.new_api_c( 'WINUSERAPI BOOL WINAPI SymCleanup( __in HANDLE hProcess );', DBGHELP_PATH )
			::Metasm::WinAPI.new_api_c( 'WINUSERAPI DWORD WINAPI SymSetOptions( DWORD SymOptions );', DBGHELP_PATH )
			::Metasm::WinAPI.new_api_c( 'WINUSERAPI BOOL WINAPI SymInitialize( HANDLE hProcess, LPCSTR UserSearchPath, BOOL fInvadeProcess );', DBGHELP_PATH )
			::Metasm::WinAPI.new_api_c( 'WINUSERAPI BOOL WINAPI SymFromName( HANDLE hProcess, LPCSTR Name, __inout LPSYMBOL_INFO Symbol );', DBGHELP_PATH )
			::Metasm::WinAPI.new_api_c( 'WINUSERAPI DWORD64 WINAPI SymLoadModuleEx( HANDLE hProcess, HANDLE hFile, LPCSTR ImageName, LPCSTR ModuleName, DWORD64 BaseOfDll, DWORD DllSize, LPVOID Data, DWORD Flags );', DBGHELP_PATH )
			::Metasm::WinAPI.new_api_c( 'WINUSERAPI BOOL WINAPI SymFromAddr( __in HANDLE hProcess, __in DWORD64 Address, __out_opt DWORD64 * Displacement, __inout LPSYMBOL_INFO Symbol );', DBGHELP_PATH )
			::Metasm::WinAPI.new_api_c( 'WINUSERAPI BOOL WINAPI SymFromIndex( __in HANDLE hProcess, __in DWORD64 BaseOfDll, __in DWORD Index, __inout LPSYMBOL_INFO Symbol );', DBGHELP_PATH )
			::Metasm::WinAPI.new_api_c( 'WINUSERAPI BOOL WINAPI SymRefreshModuleList( __in HANDLE hProcess );', DBGHELP_PATH )
			::Metasm::WinAPI.new_api_c( 'WINUSERAPI BOOL WINAPI SymSetSearchPath( __in HANDLE hProcess, __in_opt LPCSTR SearchPath );', DBGHELP_PATH )

			::Metasm::WinAPI.new_api_c( 'typedef struct _MODULEINFO {
				LPVOID lpBaseOfDll;
				DWORD  SizeOfImage;
				LPVOID EntryPoint;
			} MODULEINFO, *LPMODULEINFO;', PSAPI_PATH )
			
			::Metasm::WinAPI.new_api_c( 'WINUSERAPI BOOL WINAPI GetModuleInformation( __in HANDLE hProcess, __in HMODULE hModule, __out LPMODULEINFO lpmodinfo, __in DWORD cb );', PSAPI_PATH )

			class ProcessSymbols
				
				attr_reader :pid, :handle, :addrsz

				include Metasm
				
				def self.init( extra_symbol_server=nil )
			
					dbghelp = ::Metasm::WinAPI.loadlibrarya( DBGHELP_PATH )
					::Metasm::WinAPI.loadlibrarya( SYMSRV_PATH )
					::Metasm::WinAPI.loadlibrarya( PSAPI_PATH )

					# XXX: Ideally we could use Metasm to do something like:
					# ::Metasm::WinAPI.symfunctiontableaccess64.address
					# instead of having to call GetProcAddress() but for now
					# this will have to do.
					
					@@symfunctiontableaccess64 = ::Metasm::WinAPI.getprocaddress( dbghelp, "SymFunctionTableAccess64" )
					@@symgetmodulebase64       = ::Metasm::WinAPI.getprocaddress( dbghelp, "SymGetModuleBase64" )

					::Metasm::WinAPI.symsetoptions( ::Metasm::WinAPI.symgetoptions() | SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_INCLUDE_32BIT_MODULES );
					
					@@symPath = "SRV*#{$symbols_dir}*#{PUBLIC_SYMBOL_SERVER}"
					if( extra_symbol_server )
						@@symPath = @@symPath + ";SRV*#{$symbols_dir}*#{extra_symbol_server}"
					end
					
					print_status( "Using the symbol path '#{@@symPath}'." )
				end
				
				def initialize( pid, handle, addrsz )
					@pid    = pid
					@handle = handle
					@addrsz = addrsz

					::Metasm::WinAPI.syminitialize( @handle, @@symPath, true )
				end
				
				def refresh_symbols
					::Metasm::WinAPI.symrefreshmodulelist( @handle )
				end
				
				def stack_walk( addrsz, process_handle, thread_handle, ctx, depth=64 )
					frames = []
					frame  = ::Metasm::WinAPI.alloc_c_struct( 'STACKFRAME64' )
					
					frame[:addrpc][:offset]    = (addrsz == 64 ? ctx['Rip'] : ctx['Eip'])
					frame[:addrpc][:Mode]      = 3
					
					frame[:addrstack][:offset] = (addrsz == 64 ? ctx['Rsp'] : ctx['Esp'])
					frame[:addrstack][:Mode]   = 3
					
					frame[:addrframe][:offset] = (addrsz == 64 ? ctx['Rbp'] : ctx['Ebp'])
					frame[:addrframe][:Mode]   = 3
					
					begin
						0.upto( depth ) do 

							success = ::Metasm::WinAPI.stackwalk64( 
								(addrsz == 64 ? IMAGE_FILE_MACHINE_AMD64 : IMAGE_FILE_MACHINE_I386),
								process_handle, 
								thread_handle, 
								frame, 
								ctx.c_struct,
								0, 
								@@symfunctiontableaccess64,
								@@symgetmodulebase64,  
								0
							)
							
							break if not success or success == 0 or frame[:addrpc][:offset] == 0

							frames << frame[:addrpc][:offset]
						end
					rescue
					end
					
					return frames
				end
				
				def name2address( imagebase, imagename, functionname )

					#imagebase64 = [ imagebase ].pack('Q').unpack( 'Q' ).first
					
					ret = ::Metasm::WinAPI.symloadmoduleex( @handle, 0, imagename, 0, imagebase, 0, 0, 0 )
					if( ret == 0 and ::Metasm::WinAPI.getlasterror() != 0 ) # ERROR_SUCCESS == 0
						return nil
					end

					# Note: passing in :sizeofstruct => :size and then subtracting the maxnamelen 
					# seems to segfault the ruby vm (ruby 2.0.0p353 (2013-11-22) [x64-mingw32])
					
					sym = ::Metasm::WinAPI.alloc_c_struct( 'SYMBOL_INFO', :maxnamelen => 512 )
					
					sym[:sizeofstruct] = sym.sizeof - sym[:maxnamelen]
					
					if( ::Metasm::WinAPI.symfromname( @handle, functionname, sym ) != 1 )
						return nil
					end

					return sym[:address]
				end
				
				def address2symbol( address )
					
					result = ''
					
					begin
						sym = ::Metasm::WinAPI.alloc_c_struct( 'SYMBOL_INFO', :maxnamelen => 512 )
						
						sym[:sizeofstruct] = sym.sizeof - sym[:maxnamelen]
						
						disp = 0
						
						success = ::Metasm::WinAPI.symfromaddr( @handle, address, disp, sym )
						
						raise '' if( not success or success == 0 )
						
						mod_name = @modules[ sym[:modbase] ]
						
						raise '' if( not mod_name or mod_name.empty? )
						
						pos = mod_name.rindex( '\\' )
						if( pos )
							mod_name = mod_name[ pos + 1, mod_name.length - pos ]
						end
						
						pos = mod_name.rindex( '.' )
						if( pos )
							mod_name = mod_name[ 0, pos ]
						end

						result = "#{ mod_name }!#{ sym[:name].to_strz }"
						
					rescue
						result = ''
					end
					
					return result
				end
				
				def address2moduleoffset( address )
					
					result = ''
					
					begin

						base = ::Metasm::WinAPI.symgetmodulebase64( @handle, address )
						
						raise '' if( not base or base == 0 )
						
						mod_name = @modules[ base ]
					
						raise '' if( not mod_name or mod_name.empty? )
						
						pos = mod_name.rindex( '\\' )
						if( pos )
							mod_name = mod_name[ pos + 1, mod_name.length - pos ]
						end
						
						pos = mod_name.rindex( '.' )
						if( pos )
							mod_name = mod_name[ 0, pos ]
						end
						
						result = "#{ mod_name }!offset_#{ ( @addrsz == 64 ? '%016X' : '%08X' ) % (address - base) }"
					rescue
						result = ''
					end
					
					return result
				end
				
			end
			
		end
		
	end
	
end
