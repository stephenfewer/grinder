#
# Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
# Licensed under a 3 clause BSD license (Please see LICENSE.txt)
# Source code located at https://github.com/stephenfewer/grinder
#

require 'net/http'
require 'base64'
require 'core/logging'
require 'core/webstats'
require 'core/crypt'

			
module Grinder

	module Core
	
		module Debug
		
			class DebuggerException < ::Exception

				attr_reader :pid
				
				def initialize( browser, dst_dir, type, pid, data, hash )
					super()
					@browser  = browser
					@dst_dir  = dst_dir
					@type     = type
					@pid      = pid
					@data     = data
					@hash     = hash
					@time     = ::Time.new.strftime( "%Y-%m-%d %H:%M:%S" )
				end

				def log( crash_data, log_data, verbose=false )
					
					print_alert( "" )
					print_alert( "Caught a #{@type} in #{@browser} process #{@pid} at #{@time} with a crash hash of #{@hash[0]}.#{@hash[1]}" )

					if( $webstats_baseurl and $webstats_key )
						begin
							fuzzer = 'Unknown'
							# Issue a request to the Grinder server to get its current fuzzer...
							begin
								uri      = ::URI.parse( "http://#{$server_address}:#{$server_port}/current_fuzzer" )
								http     = Net::HTTP.new( uri.host, uri.port )
								request  = Net::HTTP::Get.new( uri.request_uri )
								response = http.request( request )

								if( response.code.to_i == 200 )
									fuzzer = response['fuzzer']
								end
							rescue ::Exception => e
								print_error( "Getting the Grinder servers current fuzzer failed: '#{e.message}'" )
							end
							
							# log this crash to the grinder web server...
							web = ::Grinder::Core::WebStats.new( $grinder_node, $webstats_baseurl, $webstats_key, $webstats_username, $webstats_password, $webstats_https )
							success = web.add_crash( @time, @browser, @hash, @type, fuzzer, crash_data ? crash_data : '', log_data ? log_data : '' )
							if( success )
								print_alert( "Posted crash to '#{$webstats_baseurl}'" )
							else
								print_error( "Failed to post crash to '#{$webstats_baseurl}'" )
							end
						rescue ::Exception => e
							print_error( "Logging the crash failed: '#{e.message}'" )
						end
					end
					
					print_alert( "" )
					
					if( verbose )
						@data.each_line do | line |
							print_alert( line )
						end
						print_alert( "" )
					end
				end
				
				def save_crash()
					
					text = nil
					
					begin
						crash_dir = "#{ @dst_dir }#{ @dst_dir.end_with?('\\') ? '' : '\\' }#{@browser}\\"
						
						if( not ::Dir.exists?( crash_dir ) )
							::Dir.mkdir( crash_dir )
						end
						
						crash_file = nil

						0.upto( 0xFFFF ) do | count |
							crash = "#{crash_dir}#{@hash[0]}.#{@hash[1]}#{ count > 0 ? '.'+count.to_s : '' }.crash"
							if( not ::File.exists?( crash ) )
								crash_file = crash
								break
							end
						end

						raise if not crash_file

						text  = ''
						text << "\n"
						text << "Caught a #{@type} in process #{@pid} at #{@time} with a crash hash of #{@hash[0]}.#{@hash[1]}\n"
						text << "\n"
						@data.each_line do | line |
							text << line
						end
						text << "\n"
						
						if( $crashes_encrypt )
							public_key = OpenSSL::PKey::RSA.new( ::File.read( $public_key_file ) )

							text = Grinder::Core::Crypt.encrypt( public_key, text )
						end
						
						::File.open( crash_file, 'w' ) do | dest |
							dest.write( text )
						end
								
					rescue
						text = nil
					end
					
					return text
				end
				
				def save_log( src_file )
					success = false
					text    = nil
					
					begin	
						sleep( 5 )
						
						::File.open( src_file, 'r' ) do | src |
							
							log_dir = "#{ @dst_dir }#{ @dst_dir.end_with?('\\') ? '' : '\\' }#{@browser}\\"
							
							if( not ::Dir.exists?( log_dir ) )
								::Dir.mkdir( log_dir )
							end
							
							log_file = nil

							0.upto( 0xFFFF ) do | count |
								log = "#{log_dir}#{@hash[0]}.#{@hash[1]}#{ count > 0 ? '.'+count.to_s : '' }.log"
								if( not ::File.exists?( log ) )
									log_file = log
									break
								end
							end

							raise if not log_file
							
							text = src.read( src.stat.size )
							
							if( $crashes_encrypt )
								public_key = OpenSSL::PKey::RSA.new( ::File.read( $public_key_file ) )

								text = Grinder::Core::Crypt.encrypt( public_key, text )
							end
							
							::File.open( log_file, 'w' ) do | dest |
								dest.write( text )
							end
					
							success = true
						end
						
						# if successfull, delete the origional src_file
						if( success )
							::File.delete( src_file )
						else
							text = nil
						end
						
					rescue
						text = nil
					end
					
					return text
				end
			end
	
		end
	
	end
	
end
