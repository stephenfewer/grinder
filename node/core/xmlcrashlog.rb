#
# Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
# Licensed under a 3 clause BSD license (Please see LICENSE.txt)
# Source code located at https://github.com/stephenfewer/grinder
#

require 'rexml/document'
require 'core/crypt'

class XmlCrashLog

	attr_reader :log_file

	def initialize( log_file, key=nil, keypass=nil, elem_prefix='id_' )
		@log_file    = log_file
		@key         = key
		@keypass     = keypass
		@log_lines   = ::Array.new
		@log_elems   = 0
		@elem_prefix = elem_prefix
	end
	
	def parse
		document = nil
		data     = nil
		
		begin
			if( @key )
				data = ::File.read( @log_file ).strip
			
				private_key = OpenSSL::PKey::RSA.new( ::File.read( @key ), @keypass )
			
				data = Grinder::Core::Crypt.decrypt( private_key, data )
			else
				data = ::File.read( @log_file )
			end
			
			# just some fixups for an older version of logging
			data = data.gsub( "<div>", '&lt;div&gt;' )
			data = data.gsub( "<p>", '&lt;p&gt;' )
			data = data.gsub( "</p>", '&lt;/p&gt;' )
			
			data = data.gsub( "\n", '' )

			if( not data.start_with?( '<fuzzer' ) )
				data = '<fuzzer name="" browser="">' + data
			end
			
			if( not data.end_with?( '</fuzzer>' ) )
				data = data + '</fuzzer>'
			end
			
			data = "<?xml version='1.0'?>" + data
			
			document = ::REXML::Document.new( data )
			
		rescue
			p $!
			data     = nil
			document = nil
		end
		
		return false if not data or not document

		document.elements.each do | root |
		
			next if( root.name.downcase != 'fuzzer' )
			
			root.each do | element1 |
			
				next if( element1.name.downcase != 'log' )
				
				log = ::Hash.new
				
				element1.each do | element2 |
					if( element2.name == 'idx' or element2.name == 'count' )
						log[element2.name] = element2.text.to_i
					elsif( element2.name == 'message' )
						message = element2.text
						
						message = message.gsub( '&lt;', '<' )
						message = message.gsub( '&gt;', '>' )
						message = message.gsub( '&amp;', '&' )
						message = message.gsub( '&quot;', '"' )
						message = message.gsub( '&apos;', '\'' )
						message = message.gsub( '&nbsp;', ' '  )
			
						log[element2.name] = message
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
				if( log['message'].include?( @elem_prefix + count.to_s ) )
					return count_log_ids.call( count + 1 )
				end
			end
			return count - 1
		end
		
		@log_elems = count_log_ids.call( 0 )
		
		return true
	end

	# returns an array of log idx's which pass any restrictions (via opts/skip_elem/skip_idx)
	def generate_idxs( opts={}, skip_elem=[], skip_idx=[] )
		idx = []
		enumerate_log( opts, skip_elem, skip_idx ) do | log |
			idx << log['idx']
		end
		return idx
	end
	
	# returns an array of log elements which pass any restrictions (via opts/skip_elem/skip_idx)
	def generate_elems( opts={}, skip_elem=[], skip_idx=[] )
		elems = []
		0.upto( @log_elems ) do | i |
			elem = @elem_prefix + i.to_s
			if( skip_elem.include?( elem ) )
				next
			end
			elems << elem
		end
		return elems
	end
	
	def enumerate_log( opts={}, skip_elem=[], skip_idx=[] )
		@log_lines.each do | log |
		
			if( skip_idx.include?( log['idx'] ) )
				next
			end

			message = log['message']

			skip = false
			
			skip_elem.each do | elem_id |			
				if( message.index( elem_id ) )
					skip = true
					break
				end
			end
			
			next if skip
			
			if( message.start_with?( '/*' ) and message.end_with?( '*/' ) )
				next if( not opts['print_code_comments'] )
			end
			
			if( message.start_with?( '//' ) )
				next if not opts['print_message_comments']
			end
			
			yield log
		end
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
		html << "\t\t<meta http-equiv='Cache-Control' content='no-cache'/>\n"
		html << "\t" << opts['testcase_head'] << "\n" if opts['testcase_head']
		html << "\t\t<title>#{title}</title>\n"
		html << "\t\t<style>\n"
		html << "\t\t\t" << opts['testcase_style'] << "\n" if opts['testcase_style']
		html << "\t\t</style>\n"
		html << "\t\t<script type='text/javascript' src='logging.js'></script>\n"
		html << "\t\t<script>\n"
		html << "\t\t\t" << opts['testcase_script'] << "\n" if opts['testcase_script']
		html << "\t\t\tfunction testcase()\n"
		html << "\t\t\t{\n"
		html << "\t\t\t" << opts['testcase_prepend_function'] << "\n" if opts['testcase_prepend_function']
		
		html << "\n"
		
		generate_elems( opts, skip_elem, skip_idx ).each do | elem |
			html << "\t\t\t\tvar #{elem} = null;\n"
		end

		html << "\n"
		
		enumerate_log( opts, skip_elem, skip_idx ) do | log |
		
			message = log['message']
			
			if( opts['testcase_fixups'] )
				opts['testcase_fixups'].each do | key, value |
					message = message.gsub( key, value )
				end
			end
			
			if( opts['uncomment_code_comments'] and message.start_with?( '/*' ) and message.end_with?( '*/' ) )
				message = message[2, message.length-4]
			end
			
			if( log['count'] > 1 )
				html << "\t\t\t\tfor( var i=0 ; i<#{log['count']} ; i++ ) {\n"
			end
			
			tabs = log['count'] > 1 ? "\t\t\t\t\t" : "\t\t\t\t"
			
			if( opts['try_catch'] and not message.start_with?( '//' ) )
				html << "#{tabs}try { #{message} } catch(e){}\n"
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