#
# Global configuration for this Grinder node.
#

################################################################################
#                         You must edit these to suit                          #
################################################################################

# A unique node name to identify this Grinder node instance...
$grinder_node             = 'G1'

# Configure any remote grinder web server to record crashes...
# Set to nil to disable this feature.
# Note: dont specify the http/https part.
$webstats_baseurl         = '192.168.1.1/status.php'
# Use the same key you used when installing the Grinder web server...
$webstats_key             = 'AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPP'
# If using basic auth, set these...
$webstats_username        = nil
$webstats_password        = nil
# If using HTTPS, set this to true (Note certs are not verified, see webstats.rb)...
$webstats_https           = false

# The path to your local symbol cache (must be able to write to this dir)
$symbols_dir              = 'C:\\symbols\\'

################################################################################
#                     You might need to edit these to suit                     #
################################################################################

# The directory to save the crash and log files.
# Note: If you run grinder from the node directory (e.g. \grinder\node\>ruby grinder.rb) then this path can be relative, otherwise specify an absolute path.
$crashes_dir              = '.\\crashes\\'

# The path to your fuzzers directory...
$fuzzers_dir              = '.\\fuzzer\\'

# Set to true in order to encrypt the .crash and .log files (Recommended if you are using a grinder web server for logging as these files are transmitted to the server).
# Note: If you run grinder from the node directory (e.g. \grinder\node\>ruby grinder.rb) then this path can be relative, otherwise specify an absolute path.
$crashes_encrypt          = false
# An RSA public key to encrypt the crash and log files before transmitting to the remote grinder server.
# Note: you can use the crypto.rb utility to generate suitable keys and encrypt/decrypt data.
$public_key_file          = '.\\public.pem'

# Configure the local web server which servers the fuzzer testcases...
# Note: This is _not_ the address for the remote grinder server used for recording crashes (see above), and this can probably be left as 127.0.0.1.
# Note: If you do need to change this dont use '0.0.0.0', instead specify an actual IP address so we can contact the server.
$server_address           = '127.0.0.1'
# If you are runnning more than one node on the same system you will need to change this to avoid a conflict.
$server_port              = 8080

################################################################################
#                     You probably dont need to edit these                     #
################################################################################

# The temporary location to write the log files during fuzzing (must be writeable from a Low integrity process).
# Note: %USERNAME% will be resolved at run time to the current user running the node.
# Note: You can also use a RAM Disk for this location as it is only for temporary logging while the fuzzers are running (Still must be writeable from a Low integrity process).
$logger_dir               = 'C:\\Users\\%USERNAME%\\AppData\\Local\\Temp\\Low\\'
# On older systems (2003/XP) you will need to use this directory...
#$logger_dir              = 'C:\\Documents and Settings\\%USERNAME%\\Local Settings\\Temp\\'

# A seed value for generating the crash hashes, only modify if you want your hashes different from other peoples/nodes.
$hash_seed                = 'A4954BC7ABD1151282A0B17DBC67BF07'

# If more then 1 fuzzer is available to this grinder node, we can swap the fuzzers every N testcases.
$swap_fuzzer_count        = 10000

# The number of minutes to wait before killing the debugger (and attached browser process) and 
# restart from the beginning to avoid browser memory leaks consuming too much system memory. 
# Set to nil to disable this feature. Must be greater than 5 minutes.
$debugger_restart_minutes = 30

# Configure the internet explorer browser...
# Note: %PROGRAMFILES32% gets resolved to 'Program Files' on 32-bit systems and 'Program Files (x86)' on 64-bit systems.
$internetexplorer_exe     = 'C:\\%PROGRAM_FILES_32%\\Internet Explorer\\iexplore.exe'
# If heap hooking is activated, then enable the recording of allocations from these modules...
$internetexplorer_logmods = [ 'mshtml.dll', 'iepeers.dll', 'urlmon.dll', 'msxml3.dll','jscript.dll', 'jscript9.dll', 'ieframe.dll' ]

# Configure the chrome browser...
$chrome_exe               = 'C:\\%PROGRAM_FILES_32%\\Google\\Chrome\\Application\\chrome.exe'

# Configure the firefox browser...
$firefox_exe              = 'C:\\%PROGRAM_FILES_32%\\Mozilla Firefox\\firefox.exe'

# Configure the safari browser...
$safari_exe               = 'C:\\%PROGRAM_FILES_32%\\Safari\\Safari.exe'

# Configure the opera browser...
$opera_exe                = 'C:\\%PROGRAM_FILES_32%\\Opera\\opera.exe'

################################################################################
#         Extra configuration for generating testcases from log files          #
################################################################################
# These options will get merged with the options in testcase.rb for use when generating a testcase via a log file (Note: not used during fuzzing).
$testcase_opts = {
	# surround each logged javascript line in the testcase() function with a try/catch block
	'try_catch'                 => true,
	# if a single log message just contains a comment, print it or not.
	# Note: code snippits should be commented with /* ...code... */ while normal comment messages should be commented with // ...message...
	'print_code_comments'       => true,
	'print_message_comments'    => true,
	# if you print code comments (/* ...code... */) you can choose to uncomment them so the code is processed as code.
	'uncomment_code_comments'   => false,
	# include the following inside the testcases <style>...</style>
	'testcase_style'            => '',
	# include the following inside the testcases <script>...</script>
	'testcase_script'           => '',
	# include the following at the begining of the testcases testcase() function
	'testcase_prepend_function' => '',
	# include the following at the end of the testcases testcase() function
	'testcase_append_function'  => '',
	# help fixup any issues with your testcases by gsubbing the key with the value (handy if you previously miss-logged something)
	'testcase_fixups'           => {},
	# include the following inside the testcases <head>...</head>
	'testcase_head'             => '',
	# include the following inside the testcases <body>...</body>
	'testcase_body'             => ''
}