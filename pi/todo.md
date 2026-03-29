## Server todo
* consider not binding to port 0 since a lot of firewalls and administrations will have that blocked
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

\# specifies the port that should be used by the server
port=8080
