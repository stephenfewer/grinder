#
# Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
# Licensed under a 3 clause BSD license (Please see LICENSE.txt)
# Source code located at https://github.com/stephenfewer/grinder
#

require 'base64'
require 'digest/sha2'
require 'openssl'

module Grinder

	module Core

		class Crypt
		
			def Crypt.encrypted?( file, split_char=';' )
				begin
					::File.open( file, 'r' ) do | f |
					
						data  = f.read( f.stat.size )
						
						parts = data.split( split_char )

						if( not parts or parts.length != 6 or parts[0].to_i != parts[3].length or parts[1].to_i != parts[4].length or parts[2].to_i != parts[5].length )
							return false
						end
						
						return true
					end
				rescue
				end
				return false
			end
			
			def Crypt.encrypt( rsa_key, data, split_char=';', cipher_algorithm='aes-256-cbc' )
				
				if( not rsa_key.public? )
					return nil
				end
				
				cipher = ::OpenSSL::Cipher.new( cipher_algorithm )
				
				secret = 128.times.map { '!'.unpack('C').first.+( rand( '~'.unpack('C').first - '!'.unpack('C').first ) ).chr }.join
				
				cipher_key = ::Digest::SHA256.digest( secret )
				cipher_iv  = cipher.random_iv
				
				cipher.encrypt
				cipher.key = cipher_key
				cipher.iv  = cipher_iv
				
				ciphertext = ''
				ciphertext << cipher.update( data )
				ciphertext << cipher.final
				
				ciphertext = ::Base64.encode64( ciphertext ).gsub( "\n", '' )
				
				encrypted_cipher_key = ::Base64.encode64( rsa_key.public_encrypt( cipher_key ) ).gsub( "\n", '' )
				
				encrypted_cipher_iv  = ::Base64.encode64( rsa_key.public_encrypt( cipher_iv ) ).gsub( "\n", '' )
				
				return "#{encrypted_cipher_key.length}#{split_char}#{encrypted_cipher_iv.length}#{split_char}#{ciphertext.length}#{split_char}#{encrypted_cipher_key}#{split_char}#{encrypted_cipher_iv}#{split_char}#{ciphertext}"
			end
				
			def Crypt.decrypt( rsa_key, data, split_char=';', cipher_algorithm='aes-256-cbc' )
				
				if( not rsa_key.private? )
					return nil
				end
				
				parts = data.split( split_char )

				if( not parts or parts.length != 6 or parts[0].to_i != parts[3].length or parts[1].to_i != parts[4].length or parts[2].to_i != parts[5].length )
					return nil
				end
				
				encrypted_cipher_key = ::Base64.decode64( parts[3] )
				encrypted_cipher_iv  = ::Base64.decode64( parts[4] )
				ciphertext           = ::Base64.decode64( parts[5] )
				
				cipher_key = rsa_key.private_decrypt( encrypted_cipher_key )
				
				cipher_iv  = rsa_key.private_decrypt( encrypted_cipher_iv )
				
				cipher = ::OpenSSL::Cipher.new( cipher_algorithm )
				
				cipher.decrypt
				cipher.key = cipher_key
				cipher.iv  = cipher_iv
				
				plaintext  = cipher.update( ciphertext )
				plaintext << cipher.final
				
				return plaintext
			end
				
		end
		
	end
	
end

if( $0 == __FILE__ )

	origional_data = (1+rand( 1024 )).times.map { '!'.unpack('C').first.+( rand( '~'.unpack('C').first - '!'.unpack('C').first ) ).chr }.join

	rsa = ::OpenSSL::PKey::RSA.generate( 1024 )
	
	encrypted = Grinder::Core::Crypt.encrypt( rsa, origional_data )
	
	decrypted = Grinder::Core::Crypt.decrypt( rsa, encrypted )
	
	if( decrypted == origional_data )
		puts "pass."
	else
		puts "fail."
	end

end
