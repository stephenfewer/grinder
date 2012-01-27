#
# Global configuration for this Grinder node.
#

# A unique node name to identify this Grinder node instance...
$grinder_node = 'G1'

# A seed value for generating the crash hashes, only modify if you want your hashes different from other peoples/nodes.
$hash_seed = 'A4954BC7ABD1151282A0B17DBC67BF07'

# Configure the local web server which servers the fuzzer testcases...
# Note: This is not the address for the remote grinder server used for recording crashes (see further below), and this can probably be left as 127.0.0.1.
# Note: If you do need to change this dont use '0.0.0.0', instead specify an actual IP address so we can contact the server.
$server_address = '127.0.0.1'
# If you are runnningmore than one node on the same system you will need to change this to avoid a conflict.
$server_port    = 8080

# The directory to place the crash and log files.
# Note: If you run grinder from the node directory (e.g. \grinder\node\>ruby grinder.rb) then this path can be relative, otherwise specify an absolute path.
$crashes_dir = '.\\crashes\\'

# The path to your fuzzers...
$fuzzers_dir = '.\\fuzzer\\'

# The path to your local symbol cache (must be able to write to this dir)
$symbols_dir = 'C:\\symbols\\'

# If more then 1 fuzzer is available to this grinder node, we can swap the fuzzers every N testcases.
$swap_fuzzer_count = 100000

# The number of minutes to wait before killing the debugger (and attached browser process) and 
# restart from the beginning to avoid browser memory leaks consuming too much system memory. 
# Set to nil to disable this feature.
$debugger_restart_minutes = 60

# The directory to write the log files (must be writeable from a Low integrity process).
# Note: %USERNAME% will be resolved at run time to the current user running the node.
$logger_dir  = 'C:\\Users\\%USERNAME%\\AppData\\Local\\Temp\\Low\\'
# On older systems (2003/XP) you will need to use this directory...
#$logger_dir  = 'C:\\Documents and Settings\\%USERNAME%\\Local Settings\\Temp\\'

# Configure the internet explorer browser...
$internetexplorer_exe = 'C:\\Program Files\\Internet Explorer\\iexplore.exe'
#$internetexplorer_exe = 'C:\\Program Files (x86)\\Internet Explorer\\iexplore.exe'

# Configure the chrome browser...
$chrome_exe = 'C:\\Users\\%USERNAME%\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe'

# Configure the firefox browser...
$firefox_exe = 'C:\\Program Files\\Mozilla Firefox\\firefox.exe'
#$firefox_exe = 'C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe'

# Configure the safari browser...
$safari_exe = 'C:\\Program Files\\Safari\\Safari.exe'
#$safari_exe = 'C:\\Program Files (x86)\\Safari\\Safari.exe'

# Configure the opera browser...
$opera_exe = 'C:\\Program Files\\Opera\\opera.exe'
#$opera_exe = 'C:\\Program Files (x86)\\Opera\\opera.exe'

# Set to true in order to encrypt the .crash and .log files (Recommended if you are using a grinder web server for logging as
# these files are transmitted to the server).
# Note: If you run grinder from the node directory (e.g. \grinder\node\>ruby grinder.rb) then this path can be relative, otherwise specify an absolute path.
$crashes_encrypt = false
# An RSA public key to encrypt the crash and log files before transmitting to the remote grinder server.
# Note: you can use the crypto.rb utility to generate suitable keys and encrypt/decrypt data.
$public_key_file = '.\\public.pem'

# Configure any remote grinder web server to record crashes...
# Set to nil to disable this feature.
# Note: dont specify the http/https part.
$webstats_baseurl  = '192.168.1.1/status.php'
# Use the same key you used when installing the Grinder web server...
$webstats_key      = 'AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPP'
# If using basic auth, set these...
$webstats_username = nil
$webstats_password = nil
# If using HTTPS, set this to true (Note certs are not verified, see webstats.rb)...
$webstats_https    = false
# Post fuzz status to grinder web server every N minutes.
$webstats_update_minutes = 5

# The logger dll (This need not be changed).
$logger_dll  = 'grinder_logger.dll'