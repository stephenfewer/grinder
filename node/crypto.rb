#
# Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
# Licensed under a 3 clause BSD license (Please see LICENSE.txt)
# Source code located at https://github.com/stephenfewer/grinder
#


$:.unshift( '.' )

require 'core/logging'
require 'core/crypt'

def usage

	print_simple( 'To generate a new RSA key pair:' )
	print_simple( '    >ruby crypto.rb /generate /pubkey public.pem /privkey private.pem [/keysize 4096] [/keypass MyKeYpAsSwOrD]' )
	print_simple( '' )
	print_simple( 'To encrypt a file' )
	print_simple( '    >ruby crypto.rb /encrypt /pubkey public.pem /inputfile plaintext.txt [/outputfile ciphertext.txt]' )
	print_simple( '' )
	print_simple( 'To decrypt a file' )
	print_simple( '    >ruby crypto.rb /decrypt /privkey private.pem /inputfile ciphertext.txt [/outputfile plaintext.txt] [/keypass MyKeYpAsSwOrD]' )
	
	::Kernel.exit
end

if( $0 == __FILE__ )
	verbose    = true
	generate   = false
	encrypt    = false
	decrypt    = false
	keysize    = 2048
	keypass    = nil
	pubkey     = nil
	privkey    = nil
	inputfile  = nil
	outputfile = nil
	
	ARGV.each_index do | index |
		case ARGV[index].downcase
			when '/help', '-help', '--help', '-h', '/h', '/?'
				usage
			when '/quiet', '-quiet', '--quiet', '-q', '/q'
				verbose = false
			when '/generate', '-generate', '--generate', '-g', '/g'
				generate = true
			when '/encrypt', '-encrypt', '--encrypt', '-e', '/e'
				encrypt = true
			when '/decrypt', '-decrypt', '--decrypt', '-d', '/d'
				decrypt = true
			when '/keysize', '-keysize', '--keysize', '-s', '/s'
				keysize = ARGV[index+1].to_i
			when '/keypass', '-keypass', '--keypass', '-p', '/p'
				keypass = ARGV[index+1]
			when '/pubkey', '-pubkey', '--pubkey'
				pubkey = ARGV[index+1]
			when '/privkey', '-privkey', '--privkey'
				privkey = ARGV[index+1]
			when '/inputfile', '-inputfile', '--inputfile', '-i', '/i', '-in', '/in'
				inputfile = ARGV[index+1]
			when '/outputfile', '-outputfile', '--outputfile', '-o', '/o', '-out', '/out'
				outputfile = ARGV[index+1]
			end
	end
	
	print_init( 'CRYPTO', verbose )
	
	if( generate )
	
		if( not pubkey )
			print_error( "Can't generate without a public key file specified to save to (specify one with /pubkey on the command line)." )
			::Kernel.exit( false )
		end
		
		if( not privkey )
			print_error( "Can't generate without a private key file specified to save to (specify one with /privkey on the command line)." )
			::Kernel.exit( false )
		end
		
		if( not keypass )
			print_warning( "Generating an RSA key pair with no password for the private key (specify one with /keypass on the command line)." )
		end
		
		print_status( "Generating an RSA key pair (#{keysize} bits)." )
		
		key_pair = OpenSSL::PKey::RSA.generate( keysize )
		
		print_status( "Saving the public key to '#{pubkey}'." )
		
		::File.open( pubkey, 'wb' ) do | f |
			f.write( key_pair.public_key )
		end
			
		print_status( "Saving the private key to '#{privkey}'. Keep it private!" )
		
		::File.open( privkey, 'wb' ) do | f |
			if( keypass )
				cipher = OpenSSL::Cipher::Cipher.new( 'aes-256-cbc' )
				f.write( key_pair.to_pem( cipher, keypass ) )
			else
				f.write( key_pair.to_pem )
			end
		end
	
	elsif( encrypt )
		
		if( not pubkey )
			print_error( "Can't encrypt without a public key (specify one with /pubkey on the command line)." )
			::Kernel.exit( false )
		end
		
		if( not inputfile )
			print_error( "Can't encrypt without an input file (specify one with /inputfile on the command line)." )
			::Kernel.exit( false )
		end
				
		print_status( "Reading the input data from '#{inputfile}'." )
				
		inputdata  = ::File.read( inputfile )
		
		print_status( "Reading the public key from '#{pubkey}'." )
		
		public_key = OpenSSL::PKey::RSA.new( ::File.read( pubkey ) )
		
		print_status( "Encrypting the input data with the public key." )
		
		encrypted  = Grinder::Core::Crypt.encrypt( public_key, inputdata )
		
		print_status( "Writing the encrypted data to '#{outputfile ? outputfile : 'stdout' }'" )
		
		if( outputfile )
			::File.open( outputfile, 'wb' ) do | f |
				f.write( encrypted )
			end
		else
			print_simple( encrypted )
		end
		
	elsif( decrypt )
	
		if( not privkey )
			print_error( "Can't decrypt without a private key (specify one with /privkey on the command line)." )
			::Kernel.exit( false )
		end
		
		if( not inputfile )
			print_error( "Can't decrypt without an input file (specify one with /inputfile on the command line)." )
			::Kernel.exit( false )
		end
		
		inputdata  = ::File.read( inputfile ).strip
		
		private_key = OpenSSL::PKey::RSA.new( ::File.read( privkey ), keypass )
		
		decrypted = Grinder::Core::Crypt.decrypt( private_key, inputdata )
		
		if( outputfile )
			::File.open( outputfile, 'wb' ) do | f |
				f.write( decrypted )
			end
		else
			print_simple( decrypted )
		end
		
	end
	
end