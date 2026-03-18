## Server todo
* improve connection protocol using either mDNS (would require dependencies) or UDP discovery broadcast (if using UDP broadcast a timeout/fallback system should be in place where if the broadcast is not picked up in a certain amount of time the client is prompted to enter the ip manually). also maybe print out server ip on startup in case the client needs to enter it manually
* make display of tak an option
* integrate automatic daemonization as an option (note then when adding daemonization, a utility should also probably be added to display the key)
* add a key reset option that deletes the mdk file
* add support for other options to the config file

### Future CLI command options:
-mv old new, --move old new      moves the Pilan root directory from the old path to the new path and automatically writes the change to the config file  
-k, --key                                displays the transfer authentication key

### Future config file options example:
\# moves the Pilan root directory to the specified path (editing this does not affect the previous root location. To move the previous root to a new location the -mv or --move option should be used)  
pilan_root=/home/user/Pilan

\# specifies whether metadata is generated for local encryptions  
local_metadata=bool

\# specifies whether full metadata is generated for local/remote encryptions, or just the required metadata  
full_metadata=bool
