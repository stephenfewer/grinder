#
# Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
# Licensed under a 3 clause BSD license (Please see LICENSE.txt)
# Source code located at https://github.com/stephenfewer/grinder
#

require 'lib/metasm/metasm'
require 'core/logging'

module Grinder

	module Core
	
		module Debug
		
			# http://msdn.microsoft.com/en-us/library/ms681366%28v=vs.85%29.aspx
			SYMOPT_CASE_INSENSITIVE = 0x00000001
			SYMOPT_UNDNAME          = 0x00000002
			SYMOPT_DEFERRED_LOADS   = 0x00000004
			SYMOPT_DEBUG            = 0x80000000
			SYMOPT_LOAD_LINES       = 0x00000010
			SYMOPT_NO_PROMPTS       = 0x00080000

			Metasm::WinAPI.new_api_c( 'WINBASEAPI HMODULE WINAPI LoadLibraryA( __in LPCSTR lpLibFileName );', 'kernel32' )
			Metasm::WinAPI.new_api_c( 'WINBASEAPI LPVOID WINAPI GetProcAddress( __in HMODULE hModule, __in LPCSTR lpProcName );', 'kernel32' )
			Metasm::WinAPI.new_api_c( 'WINBASEAPI DWORD WINAPI WaitForSingleObject( __in HANDLE hHandle, __in DWORD dwMilliseconds );', 'kernel32' )

			Metasm::WinAPI.new_api_c( 'WINUSERAPI DWORD WINAPI WaitForInputIdle( __in HANDLE hProcess, __in DWORD dwMilliseconds );', 'user32' )

			Metasm::WinAPI.new_api_c( 'typedef struct _SYMBOL_INFO {
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
			  CHAR    Name[1];
			} SYMBOL_INFO, *LPSYMBOL_INFO;', '.\\data\\dbghelp.dll' )

			Metasm::WinAPI.new_api_c( 'WINUSERAPI DWORD WINAPI SymGetOptions( VOID );', '.\\data\\dbghelp.dll' )
			Metasm::WinAPI.new_api_c( 'WINUSERAPI BOOL WINAPI SymCleanup( __in HANDLE hProcess );', '.\\data\\dbghelp.dll' )
			Metasm::WinAPI.new_api_c( 'WINUSERAPI DWORD WINAPI SymSetOptions( DWORD SymOptions );', '.\\data\\dbghelp.dll' )
			Metasm::WinAPI.new_api_c( 'WINUSERAPI BOOL WINAPI SymInitialize( HANDLE hProcess, LPCSTR UserSearchPath, BOOL fInvadeProcess );', '.\\data\\dbghelp.dll' )
			Metasm::WinAPI.new_api_c( 'WINUSERAPI BOOL WINAPI SymFromName( HANDLE hProcess, LPCSTR Name, __inout LPSYMBOL_INFO Symbol );', '.\\data\\dbghelp.dll' )
			Metasm::WinAPI.new_api_c( 'WINUSERAPI DWORD64 WINAPI SymLoadModuleEx( HANDLE hProcess, HANDLE hFile, LPCSTR ImageName, LPCSTR ModuleName, DWORD64 BaseOfDll, DWORD DllSize, LPVOID Data, DWORD Flags );', '.\\data\\dbghelp.dll' )
			Metasm::WinAPI.new_api_c( 'WINUSERAPI BOOL WINAPI SymFromAddr( __in HANDLE hProcess, __in DWORD64 Address, __out_opt DWORD64 * Displacement, __inout LPSYMBOL_INFO Symbol );', '.\\data\\dbghelp.dll' )
			Metasm::WinAPI.new_api_c( 'WINUSERAPI BOOL WINAPI SymFromIndex( __in HANDLE hProcess, __in DWORD64 BaseOfDll, __in DWORD Index, __inout LPSYMBOL_INFO Symbol );', '.\\data\\dbghelp.dll' )
			Metasm::WinAPI.new_api_c( 'WINUSERAPI BOOL WINAPI SymRefreshModuleList( __in HANDLE hProcess );', '.\\data\\dbghelp.dll' )
			Metasm::WinAPI.new_api_c( 'WINUSERAPI BOOL WINAPI SymSetSearchPath( __in HANDLE hProcess, __in_opt LPCSTR SearchPath );', '.\\data\\dbghelp.dll' )

			class ProcessSymbols
				
				attr_reader :pid, :handle
				
				include Metasm
				
				def self.init( extra_symbol_server=nil )
			
					Metasm::WinAPI.loadlibrarya( ".\\data\\dbghelp.dll" )
					Metasm::WinAPI.loadlibrarya( ".\\data\\symsrv.dll" )
				
					symopts = Metasm::WinAPI.symgetoptions();
					symopts |= SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS 
					Metasm::WinAPI.symsetoptions( symopts );
					
					@@symPath = "SRV*#{$symbols_dir}*http://msdl.microsoft.com/download/symbols"
					if( extra_symbol_server )
						@@symPath = @@symPath + ";SRV*#{$symbols_dir}*#{extra_symbol_server}"
					end
					print_status( "Using the symbol path '#{@@symPath}'" )
				end
				
				def initialize( pid, handle )
					@pid    = pid
					@handle = handle

					Metasm::WinAPI.syminitialize( @handle, @@symPath, true )
				end
				
				def refresh_symbols
					Metasm::WinAPI.symrefreshmodulelist( @handle )
				end
				
				def name2address( imagebase, imagename, functionname )

					ret = Metasm::WinAPI.symloadmoduleex( @handle, 0, imagename, 0, imagebase, 0, 0, 0 )
					if( ret == 0 and Metasm::WinAPI.getlasterror() != 0 )
						return nil
					end
					
					sym  = [0x58].pack('L') + 0.chr*4*19 + [512].pack('L') + 0.chr*512
					
					ret = Metasm::WinAPI.symfromname( @handle, functionname, sym )
					if( ret != 1 )
						return nil
					end
					
					sizeofstruct, typeindex, reserved1, reserved2, index, size, modbase, flags, value, address_high, address_low, register, scope, tag, namelen, maxnamelen, name = sym.unpack( 'VVQQVVQVQVVVVVVVS' )

					address_low != 0 ? address_low : nil
				end
				
				def address2symbol( address, mods=nil )
					sym  = [0x58].pack('L') + 0.chr*4*19 + [512].pack('L') + 0.chr*512
					#disp = 0.chr*8
					#sym = [88,0,0,0,0,0,0,0,0,0,0,0,0,0,0,512,0].pack( 'VVQQVVQVQQVVVVVVV' ) + "\x00" * 512
					address64 = [ address ].pack('Q').unpack( 'Q' ).first
					disp = 0
					ret = Metasm::WinAPI.symfromaddr( @handle, address64, disp, sym );
					#ret = Metasm::WinAPI.symfromaddr( @handle, 0, disp, sym );
					if( ret )#and disp.unpack('L').first == 0 )
						sizeofstruct, typeindex, reserved1, reserved2, index, size, modbase, flags, value, address_high, address_low, register, scope, tag, namelen, maxnamelen, name = sym.unpack( 'VVQQVVQVQVVVVVVVS' )
						mod_name = ""
						begin
							if( not mods )
								mods = Metasm::WinOS::Process.new( @pid ).modules
							end
							mod_name = mods[ mods.index{ | mod | mod.addr == modbase } ].path.downcase 
							if( not mod_name.empty? )
								mod_name = mod_name[ mod_name.rindex('\\')+1, mod_name.length-mod_name.rindex('\\') ]
								if( mod_name.rindex('.') )
									mod_name = mod_name[ 0, mod_name.rindex('.') ]
								end
								mod_name += "!"
							end
						rescue
						end
						
						symnamelen = sym[19*4, 4].unpack('L').first

						#symbol = mod_name + sym[84,sym.length-84].gsub( "\x00", '' )
						return mod_name + sym[0x54, symnamelen]
					end
					return ''
				end
				
				def address2moduleoffset( address, mods=nil )
					if( not mods )
						mods = Metasm::WinOS::Process.new( @pid ).modules
					end
					mods.each do | mod |
						break if not mod.respond_to?( :size )
						if( address >= mod.addr and address < (mod.addr + mod.size) )
							path = mod.path.downcase
							name = ''
							if( not path.empty? )
								name = path[ path.rindex('\\')+1, path.length-path.rindex('\\') ]
								if( name.rindex('.') )
									name = name[ 0, name.rindex('.') ]
								end
							end
							return "%s!offset_%08X" % [ name, ( address - mod.addr ) ]
						end
					end
					return ''
				end
				
			end
			
		end
		
	end
	
end
