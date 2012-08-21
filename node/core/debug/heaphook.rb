#
# Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
# Licensed under a 3 clause BSD license (Please see LICENSE.txt)
# Source code located at https://github.com/stephenfewer/grinder
#

module Grinder

	module Core
	
		module Debug
		
			module HeapHook
			
				# defines/structs from ./grinder/node/source/heap/heap.h
				CONFIG_ZERO_ALLOCS             = 1
				CONFIG_RECORD_DEFAULT_HEAP     = 2
				CONFIG_SAFE_STACK_WALK         = 4
				CONFIG_PASSTHROUGH_STACK_WALK  = 8
				CONFIG_CHECK_WRITE_AFTER_FREE  = 16
				CONFIG_DISABLE_CHUNK_RECORDING = 32
				CONFIG_FLUSH_IF_RECORDS_FULL   = 64

				ALERT_WRITE_AFTER_FREE         = 1

				CALLSTACK_DEPTH                = 5
				
				RECORDTYPE_ALLOC               = 1
				RECORDTYPE_FREE                = 2
				RECORDTYPE_REALLOC             = 4
				
				INDEX_NOT_SET                  = -1
				
				Metasm::WinAPI.new_api_c( %Q|

					typedef VOID CRITICAL_SECTION;
					
					typedef struct _CHUNKRECORD
					{
						BYTE bType;
						BYTE bUnused[3];
						DWORD dwNextIndex;        // if a realloc this is -1 or and index to a subsequent realloc. if a free this is -1. if an alloc this is either -1 or and index to a subsequent realloc.
						LPVOID lpPrevChunkAddres; // only used for reallocs to stor the orig address before reallocation (easier than storing a backlink index)
						HANDLE hHeapHandle;
						LPVOID lpChunkAddress;
						DWORD dwChunkSize;
						DWORD dwFlags;
						DWORD dwFuzzerIdx;
						// this make METASM crash if we access chunkrecord[:dwcallstack] (metasm/decode.rb:169:in `decode_imm': undefined method `/' for nil:NilClass)
						//DWORD dwCallstack[#{CALLSTACK_DEPTH}];
						// so instead we have to do it this way :/
						DWORD dwCallstack0;
						DWORD dwCallstack1;
						DWORD dwCallstack2;
						DWORD dwCallstack3;
						DWORD dwCallstack4;
					} CHUNKRECORD;
					
					typedef struct _HEAPRECORD
					{
						CHUNKRECORD * pChunkBase;
						CHUNKRECORD * pChunkLimit;
						CHUNKRECORD * pChunkCurrent;
						DWORD dwChunkIndex;
						CRITICAL_SECTION * pLock;
					} HEAPRECORD;

					typedef struct _HEAPRECORDS
					{
						HEAPRECORD Busy;
						HEAPRECORD Free;
					} HEAPRECORDS;
					
					|, '.\\data\\grinder_heaphook.dll' )
				
				
				# we use a seperate class for a chunk record so we dont have to pass metasm c structures around
				# also we can include a few handy utility methods too.
				class ChunkRecord
				
					TYPE_UNKNOWN = 0
					TYPE_FREE    = 1
					TYPE_ALLOC   = 2
					TYPE_REALLOC = 3

					# \Microsoft SDKs\Windows\v7.0A\Include\WinNT.h
					HEAP_FLAGS = {
						'HEAP_NO_SERIALIZE'             => 0x00000001,
						'HEAP_GROWABLE'                 => 0x00000002,
						'HEAP_GENERATE_EXCEPTIONS'      => 0x00000004,
						'HEAP_ZERO_MEMORY'              => 0x00000008,
						'HEAP_REALLOC_IN_PLACE_ONLY'    => 0x00000010,
						'HEAP_TAIL_CHECKING_ENABLED'    => 0x00000020,
						'HEAP_FREE_CHECKING_ENABLED'    => 0x00000040,
						'HEAP_DISABLE_COALESCE_ON_FREE' => 0x00000080,
						'HEAP_CREATE_ALIGN_16'          => 0x00010000,
						'HEAP_CREATE_ENABLE_TRACING'    => 0x00020000,
						'HEAP_CREATE_ENABLE_EXECUTE'    => 0x00040000
					}
					
					attr_accessor :index, :type, :handle, :address, :prevaddress, :size , :flags, :idx, :callstack, :nextindex
					
					def initialize( index, chunkrecord_struct )
					
						@type = ChunkRecord::TYPE_UNKNOWN
					
						case chunkrecord_struct[:btype]
							when RECORDTYPE_FREE
								@type = ChunkRecord::TYPE_FREE
							when RECORDTYPE_ALLOC
								@type = ChunkRecord::TYPE_ALLOC
							when RECORDTYPE_REALLOC
								@type = ChunkRecord::TYPE_REALLOC						
						end
						
						@index       = index
						@handle      = chunkrecord_struct[:hheaphandle]
						@address     = chunkrecord_struct[:lpchunkaddress]
						@prevaddress = chunkrecord_struct[:lpprevchunkaddres]
						@size        = chunkrecord_struct[:dwchunksize]
						@flags       = chunkrecord_struct[:dwflags]
						@idx         = chunkrecord_struct[:dwfuzzeridx] == INDEX_NOT_SET ? nil : chunkrecord_struct[:dwfuzzeridx]
						@nextindex   = chunkrecord_struct[:dwnextindex] == INDEX_NOT_SET ? nil : chunkrecord_struct[:dwnextindex]
						@callstack   = []
					end
					
					def add_caller( symbol )
						@callstack << symbol
					end
					
					#def object_type
					#	@callstack.each do | caller |
					#		result = caller.scan( /\w{1,}!([\w\:]{0,})::operator new/ )
					#		if( not result.empty? )
					#			return result.first.first
					#		end
					#	end
					#	return ''
					#end
					
					def contains?( pointer )
						if( pointer >= @address and pointer < (@address + @size) )
							return true
						end
						return false
					end
					
					def is_alloc?
						@type == TYPE_ALLOC ? true : false
					end
					
					def is_realloc?
						@type == TYPE_REALLOC ? true : false
					end
					
					def is_free?
						@type == TYPE_FREE ? true : false
					end

					def flags_to_s
						result = ''
						
						if( @flags )
							HEAP_FLAGS.each do | key, value |
								if( ( @flags & value ) == value )
									result << key << ' | '
								end
							end
						end
						
						if( result.end_with?( ' | ' ) )
							result = result[ 0, result.length - 3 ]
						end
						
						if( result.empty? )
							result = 'NULL'
						end
						
						return result
					end

					def to_s
						if( is_free? )
							return "ntdll!RtlFreeHeap( 0x%08X, %s, 0x%08X ) // size=%d#{ @idx ? ", idx=%d" % @idx : '' }" % [ @handle, flags_to_s, @address, @size ]
						elsif( is_alloc? )
							return "ntdll!RtlAllocateHeap( 0x%08X, %s, %d ) // address=0x%08X#{ @idx ? ", idx=%d" % @idx : '' }" % [ @handle, flags_to_s, @size, @address ]
						elsif( is_realloc? )
							return "ntdll!RtlReAllocateHeap( 0x%08X, %s, 0x%08X, %d ) // address=0x%08X#{ @idx ? ", idx=%d" % @idx : '' }" % [ @handle, flags_to_s, @prevaddress, @size, @address ]
						end
						return ""
					end
					
					def inspect
						type = 'unknown'
						
						if( is_free? )
							type = 'free'
						elsif( is_alloc? )
							type = 'alloc'
						elsif( is_realloc? )
							type = 'realloc'
						end

						"type=%s, index=%d, handle=0x%08X, address=0x%08X, size=%d, flags=0x%08X, #{ @idx ? "idx=%d," % @idx : ',' } #{ @nextindex ? "nextindex=%d," % @nextindex : '' } callstack=%s" % [ type, @index, @handle, @address, @size, @flags, @callstack.to_s ]
					end
				end
				
				def heaphook_initialize( configflags=nil, defaultalertcallback=true )
					@heaphook_dll         = 'grinder_heaphook.dll'
					@chunk_busylist       = nil
					@chunk_freelist       = nil
					
					# CONFIG_ZERO_ALLOCS             - When allocating a new chunk, memset the chunk with 0xCC if the HEAP_ZERO_MEMORY flag is not set
					# CONFIG_RECORD_DEFAULT_HEAP     - Only process chunks from the processes default heap, otherwise process chunks from all heaps
					# CONFIG_SAFE_STACK_WALK         - When walking the stack, use a SEH wrapped function (safer/slower), otherwise dont use a SEH wrapped function (might explode/faster)
					# CONFIG_PASSTHROUGH_STACK_WALK  - Dont check the calling modules to see if a caller is from a module we are interested in (accept all modules).
					# CONFIG_CHECK_WRITE_AFTER_FREE  - When flushing the chunk records check if any freed chunk was written to after it was freed.
					# CONFIG_DISABLE_CHUNK_RECORDING - Dont record the chunk allocations/frees.

					@configflags          = configflags ? configflags : CONFIG_ZERO_ALLOCS | CONFIG_RECORD_DEFAULT_HEAP
					@defaultalertcallback = defaultalertcallback
					
					@hhmodules            = {}
					
					heaphook_modules.each do | hhmod |
						@hhmodules[ hhmod ] = false
					end
				end
				
				def heaphook_modules
					[]
				end
				
				def use_heaphook?( pid )
					return false
				end
				
				def heaphook_parse_debugstring( debugstring, pid, mods )
					
					result = debugstring.scan( /\[GRINDER-HEAP-ALERT\]     Call stack entry \d{1,}: (0x[0-9A-Fa-f]{8})/ )
					if( not result.empty? )
						
						ret_addr = result.first.first.to_i( 16 )
						
						ret_symbol = @attached[pid].address2symbol( ret_addr, mods )
						if( not ret_symbol.empty? )
							debugstring = debugstring[ 0, debugstring.index( ': 0x' ) + 2 ] + ret_symbol
						end
					end
					
					return debugstring
				end
				
				def heaphook_find_chunk( address )
					
					if( @chunk_freelist )
						@chunk_freelist.each_value do | chunkrecords |
							chunkrecords.each do | chunkrecord |
								if( chunkrecord.contains?( address ) )
									return chunkrecord
								end
							end
						end
					end
					
					if( @chunk_busylist )
						@chunk_busylist.each_value do | chunkrecords |
							chunkrecords.each do | chunkrecord |
								if( chunkrecord.contains?( address ) )
									return chunkrecord
								end
							end
						end
					end

					return nil
				end
				
				def heaphook_loader( pid, imagebase )
					print_status( "Heap Hook DLL loaded into process #{pid} @ 0x#{'%08X' % imagebase }")
					
					if( not @attached[pid].heap_logmodule )
						heap_logmodule = get_dll_export( pid, imagebase, 'HEAP_logModule' )
						if( heap_logmodule )
							@attached[pid].heap_logmodule = heap_logmodule
						else
							print_error( "Failed to resolved grinder_heap!HEAP_logModule" )
						end
					end
					
					if( not @attached[pid].heap_flush )
						heap_flush = get_dll_export( pid, imagebase, 'HEAP_flush' )
						if( heap_flush )
							@attached[pid].heap_flush = heap_flush
						else
							print_error( "Failed to resolved grinder_heap!HEAP_flush" )
						end
					end
					
					if( not @attached[pid].heap_defaultalertcallback )
						heap_defaultalertcallback = get_dll_export( pid, imagebase, 'HEAP_defaultAlertCallback' )
						if( heap_defaultalertcallback )
							@attached[pid].heap_defaultalertcallback = heap_defaultalertcallback
						else
							print_error( "Failed to resolved grinder_heap!HEAP_defaultAlertCallback" )
						end
					end
					
					if( not @attached[pid].heap_records )
						heap_records = get_dll_export( pid, imagebase, 'HEAP_records' )
						if( heap_records )
							@attached[pid].heap_records = heap_records
						else
							print_error( "Failed to resolved grinder_heap!HEAP_records" )
						end
					end
					
					heap_init = get_dll_export( pid, imagebase, 'HEAP_init' )
					if( heap_init )
					
						alertcallback = 0
						
						if( @defaultalertcallback )
							alertcallback = @attached[pid].heap_defaultalertcallback ? @attached[pid].heap_defaultalertcallback : 0;
						end
						
						struct = [ @configflags, alertcallback ].pack( 'VV' )
						
						struct_addr = Metasm::WinAPI.virtualallocex( @hprocess[pid], 0, struct.length, Metasm::WinAPI::MEM_COMMIT|Metasm::WinAPI::MEM_RESERVE, Metasm::WinAPI::PAGE_READWRITE )
						
						@mem[pid][struct_addr, struct.length] = struct
						
						Metasm::WinAPI.createremotethread( @hprocess[pid], 0, 0, heap_init, struct_addr, 0, 0 )
						
						print_status( "Heap hooking initialized for process #{pid}" )
					else
						print_error( "Failed to resolved grinder_heap!HEAP_init" )
					end
					
					if( heap_init and @attached[pid].heap_logmodule and @attached[pid].heap_flush and @attached[pid].heap_defaultalertcallback and @attached[pid].heap_records )
						return true
					end
				
					return false
				end
				
				def heaphook_parse_records( pid, mods )

					if( not use_heaphook?( pid ) or not @attached[pid].heap_records )
						return false
					end

					heaprecord_size  = Metasm::WinAPI.sizeof_c_struct( "HEAPRECORD" )
					
					# METASM cant seem to handle structures in structures so we have to do it this way instead :(
					
					busyrecords_data = @mem[pid][ @attached[pid].heap_records, heaprecord_size ]
					
					freerecords_data = @mem[pid][ @attached[pid].heap_records + heaprecord_size, heaprecord_size ]
					
					if( not busyrecords_data or not freerecords_data )
						return false
					end

					busyrecords_struct = Metasm::WinAPI.create_c_struct( "HEAPRECORD", busyrecords_data )
					
					freerecords_struct = Metasm::WinAPI.create_c_struct( "HEAPRECORD", freerecords_data )
					
					@chunk_busylist = parse_records( busyrecords_struct, pid, mods )

					@chunk_freelist = parse_records( freerecords_struct, pid, mods )
					
					return true
				end
				
			private
			
				def parse_records( heaprecord_struct, pid, mods )
					
					chunk_list = ::Hash.new
					chunkindex = heaprecord_struct[:dwchunkindex]
					chunkbase  = heaprecord_struct[:pchunkbase]

					if( chunkbase > 0 and chunkindex > 0 )
					
						chunkrecord_size = Metasm::WinAPI.sizeof_c_struct( "CHUNKRECORD" )
						
						0.upto( chunkindex - 1 ) do | index |

							chunkrecord_data = @mem[pid][ chunkbase + ( index * chunkrecord_size ), chunkrecord_size ]
								
							break if not chunkrecord_data
								
							chunkrecord_struct = Metasm::WinAPI.create_c_struct( "CHUNKRECORD", chunkrecord_data )

							chunkrecord = ChunkRecord.new( index, chunkrecord_struct )

							0.upto( CALLSTACK_DEPTH - 1 ) do | index |
								
								ret_symbol = ''
									
								ret_addr = chunkrecord_struct[ "dwcallstack#{index}" ]
									
								if( mods )
									ret_symbol = @attached[pid].address2symbol( ret_addr, mods )
								end
									
								if( ret_symbol.empty? )
									chunkrecord.add_caller( "0x%08X" % ret_addr )
								else
									chunkrecord.add_caller( "%s" % ret_symbol )
								end
							end

							if( not chunk_list.has_key?( chunkrecord.idx ) )
								chunk_list[ chunkrecord.idx ] = []
							end
								
							chunk_list[ chunkrecord.idx ] << chunkrecord
						end
						
					end
					
					return chunk_list
				end
				
			end
	
		end
	
	end

end
