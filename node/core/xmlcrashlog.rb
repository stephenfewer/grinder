#
# Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
# Licensed under a 3 clause BSD license (Please see LICENSE.txt)
# Source code located at https://github.com/stephenfewer/grinder
#

require 'rexml/document'

class XmlCrashLog

	attr_reader :log_file

	def initialize( log_file )
		@log_file  = log_file
		@log_lines = ::Array.new
		@log_ids   = 0
	end
	
	def parse
		document = nil
	
		begin
			::File.open( @log_file, 'r' ) do | f |

				xml = f.read( f.stat.size )

				# crappy fix for now, grinder_logger.dll should encode this correctly for us.
				xml = xml.gsub( '<div>', '&lt;div&gt;' )
				xml = xml.gsub( '<p>', '&lt;p&gt;' )
				xml = xml.gsub( '</p>', '&lt;/p&gt;' )
				xml = xml.gsub( "\n", '' )

				data     = "<?xml version='1.0'?><logs>" + xml + "</logs>"
				document = ::REXML::Document.new( data )
			end
		rescue
			return false
		end
		
		document.elements.each do | root |
			next if( root.name.downcase != 'logs' )
			root.each do | element1 |
				next if( element1.name.downcase != 'log' )
				log = ::Hash.new
				element1.each do | element2 |
					if( element2.name == 'idx' or element2.name == 'count' )
						log[element2.name] = element2.text.to_i
					else
						log[element2.name] = element2.text
					end
				end
				@log_lines << log
			end
		end
		
		@log_lines = @log_lines.sort_by do | log |
			log['idx']
		end
		
		count_log_ids = lambda do | count |
			@log_lines.each do | log |
				if( log['message'].include?( 'id_' + count.to_s ) )
					return count_log_ids.call( count + 1 )
				end
			end
			return count - 1
		end
		
		@log_ids = count_log_ids.call( 0 )
		
		return true
	end

	def generate_html( opts={}, skip_elem=[], skip_idx=[] )
		html  = ''
		
		result = @log_file.scan( /([a-fA-F0-9]{8}\.[a-fA-F0-9]{8})/ )
		if( not result.empty? )
			title = result.first.first
		else
			title = @log_file
		end
		
		html << "<!doctype html>\n"
		html << "<html>\n"
		html << "\t<head>\n"
		html << "\t" << opts['testcase_head'] << "\n" if opts['testcase_head']
		html << "\t\t<title>#{title}</title>\n"
		html << "\t\t<style>\n"
		html << "\t\t\t" << opts['testcase_style'] << "\n" if opts['testcase_style']
		html << "\t\t</style>\n"
		html << "\t\t<script>\n"
		html << "\t\t\t" << opts['testcase_script'] << "\n" if opts['testcase_script']
		html << "\t\t\tfunction testcase()\n"
		html << "\t\t\t{\n"
		html << "\t\t\t" << opts['testcase_prepend_function'] << "\n" if opts['testcase_prepend_function']
		html << "\n"
		0.upto( @log_ids ) do | i |
			html << "\t\t\t\tvar id_" + i.to_s + " = null;\n"
		end
		html << "\n"
		
		clone_idx = 0;
		
		@log_lines.each do | log |
		
			if( skip_idx.include?( log['idx'] ) )
				next
			end

			message = log['message']			
			message = message.gsub( '&lt;', '<' )
			message = message.gsub( '&gt;', '>' )
			message = message.gsub( '&amp;', '&' )
			message = message.gsub( '&quot;', '"' )
			message = message.gsub( '&apos;', '\'' )
			message = message.gsub( '&nbsp;', ' '  )
			
			if( opts['testcase_fixups'] )
				opts['testcase_fixups'].each do | key, value |
					message = message.gsub( key, value )
				end
			end

			skip = false
			
			skip_elem.each do | elem_id |
				if( message.index( elem_id ) )
					skip = true
					break
				end
			end
			
			next if skip
			
			if( message.start_with?( '/*' ) and message.end_with?( '*/' ) )
				next if not opts['print_code_comments']
			end
			
			if( message.start_with?( '//' ) )
				next if not opts['print_message_comments']
			end

			if( log['count'] > 1 )
				html << "\t\t\t\tfor( var i=0 ; i<#{log['count']} ; i++ ) {\n"
			end
			
			tabs = log['count'] > 1 ? "\t\t\t\t\t" : "\t\t\t\t"
			
			if( opts['try_catch'] )
				html << "#{tabs}try { #{ message} } catch(e){}\n"
			else
				html << "#{tabs}#{message}\n"
			end
			
			if( log['count'] > 1 )
				html << "\t\t\t\t}\n"
			end
		end
		
		html << "\t\t\t" << opts['testcase_append_function'] << "\n" if opts['testcase_append_function']
		html << "\t\t\t}\n"
		html << "\t\t</script>\n"
		html << "\t</head>\n"
		html << "\t<body onload='testcase();'>\n"
		html << "\t\t" << opts['testcase_body'] << "\n" if opts['testcase_body']
		html << "\t</body>\n"
		html << "</html>\n"
		
		return html
	end
	
end