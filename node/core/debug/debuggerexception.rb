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

				attr_reader :pid, :hash
				
				def initialize( browser, dst_dir, type, pid, data, hash, verified=nil )
					super()
					@browser  = browser
					@dst_dir  = dst_dir
					@type     = type
					@pid      = pid
					@data     = data
					@hash     = hash
					@time     = ::Time.new.strftime( "%Y-%m-%d %H:%M:%S" )
					@verified = verified ? verified : Grinder::Core::WebStats::VERIFIED_UNKNOWN
				end

				def set_testcase_crash
					success = true
					begin
						uri      = ::URI.parse( "http://#{$server_address}:#{$server_port}/testcase_crash" )
						http     = Net::HTTP.new( uri.host, uri.port )
						request  = Net::HTTP::Post.new( uri.request_uri )

						request.set_form_data( { 'hash' => "#{@hash[0]}.#{@hash[1]}", 'type' => @type } )

						response = http.request( request )

						if( response.code.to_i != 200 )
							success = false
						end
					rescue
						success = false
					end
					return success
				end
				
				def duplicate?
					begin
						uri      = ::URI.parse( "http://#{$server_address}:#{$server_port}/duplicate_crash" )
						http     = Net::HTTP.new( uri.host, uri.port )
						request  = Net::HTTP::Post.new( uri.request_uri )
						
						request.set_form_data( { 'hash' => "#{@hash[0]}.#{@hash[1]}" } )
						
						response = http.request( request )

						if( response.code.to_i == 200 and response['duplicate'] == 'true' )
							return true
						end
						
						if( $webstats_baseurl and $webstats_key )
							web = ::Grinder::Core::WebStats.new( $grinder_node, $webstats_baseurl, $webstats_key, $webstats_username, $webstats_password, $webstats_https )
								
							if( web.duplicate_crash( "#{@hash[0]}.#{@hash[1]}" ) )
								return true
							end
						end

					rescue
					end
					return false
				end
				
				#def get_previous_crash
				#	result = ''
				#	begin
				#		uri      = ::URI.parse( "http://#{$server_address}:#{$server_port}/previous_crash" )
				#		http     = Net::HTTP.new( uri.host, uri.port )
				#		request  = Net::HTTP::Post.new( uri.request_uri )
				#		
				#		request.set_form_data( { 'hash' => "#{@hash[0]}.#{@hash[1]}" } )
				#		
				#		response = http.request( request )
				#
				#		if( response.code.to_i == 200 )
				#			result = response['hash']
				#		end
				#	rescue
				#		result = ''
				#	end
				#	return result
				#end
				
				def get_current_fuzzer
					fuzzer = nil
					begin
						uri      = ::URI.parse( "http://#{$server_address}:#{$server_port}/current_fuzzer" )
						http     = Net::HTTP.new( uri.host, uri.port )
						request  = Net::HTTP::Post.new( uri.request_uri )
						
						response = http.request( request )

						if( response.code.to_i == 200 )
							fuzzer = response['fuzzer']
						end
					rescue
						fuzzer = nil
					end
					return fuzzer
				end
				
				def log( crash_data, log_data )

					print_alert( "" )
					print_alert( "Caught a #{@type} in #{@browser} process #{@pid} at #{@time} with a crash hash of #{@hash[0]}.#{@hash[1]}" )

					if( $webstats_baseurl and $webstats_key )
						begin
							# Issue a request to the Grinder server to get its current fuzzer...
							fuzzer = get_current_fuzzer
							if( not fuzzer )
								print_error( "Getting the Grinder servers current fuzzer failed: '#{e.message}'" )
								fuzzer = 'Unknown'
							end
							
							# log this crash to the grinder web server...
							web = ::Grinder::Core::WebStats.new( $grinder_node, $webstats_baseurl, $webstats_key, $webstats_username, $webstats_password, $webstats_https )
							success = web.add_crash( @time, @browser, @hash, @type, fuzzer, crash_data ? crash_data : '', log_data ? log_data : '', @verified )
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

						raise 'Unable to create a unique crash file name' if not crash_file

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
						
					rescue ::Exception => e
						print_error( "Error, unable to save the crash file (#{e.message})" )
						text = nil
					end
					
					return text
				end
				
				def save_log( src_file )
					success = false
					text    = nil
					
					begin	

						got_access = false

						if( ::File.exists?( src_file ) )
							0.upto( 60 ) do
								begin
									src = ::File.open( src_file, 'r' )
									if( src )
										src.close
										got_access = true
										break
									end
								rescue
									sleep( 0.5 )
								end
							end
						else
							raise 'File doesnt exist'
						end
						
						raise 'Cant access the temporary log file' if not got_access
						
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
							
							raise 'Unable to create a unique log file name' if not log_file
							
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

						raise 'Unknown Error' if not success
						
						# if successfull, delete the origional src_file
						
						deleted = false
						
						0.upto( 60 ) do
							begin
								::File.delete( src_file )
								deleted = true
								break
							rescue ::Errno::EACCES
								sleep( 0.5 )
							end
						end
						
						if( not deleted )
							print_warning( "Warning, unable to delete the temporary logging file '#{src_file}'. Please manually delete it." )
						end
		
					rescue ::Exception => e
						print_error( "Error, unable to save the log file '#{src_file}' (#{e.message})" )
						text = nil
					end
					
					return text
				end
			end
	
		end
	
	end
	
end
