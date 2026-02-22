## Docs

WIP DOCS. SOME STEPS MAY BE MISSING AND THE EXISTING STEPS NEED TO BE EXPANDED ON.

### Creating the Alpine Image for first boot

* Image Alpine Linux to boot media using Raspberry Pi Imager.
* If using a DSI display you can copy usercfg.txt from this repository to the boot media in order to use it during first boot.
* If using SSH or serial console on first boot, there may be other configuration steps required.
* Plug in boot media to the Pi and go through the Alpine Linux first time setup.
* Connect to internet to update apk packages and download hostapd.
* Set hostapd.conf file.
* Disconnect from internet, ensure wlan0 is in AP mode, and then launch hostapd. At this point the Pi should be discoverable as a wifi access point on other devices.

### Alpine Linux First Time Setup

* Alpine will boot into a shell. From there run setup-alpine.
* Next you will be asked for your preferred keyboard layout and variant. If you wish to use a standard US keyboard, you can enter us for both of these questions.
* Next you will be asked to set your system hostname. I use the hostname pilan.
* Next you will be asked to choose a network interface. Type wlan0 and press enter. 
* Next Alpine will scan for wireless networks and ask you to choose one to connect to. You probably want to connect to a network at this point as you will need to update and install some packages, and connecting to a network now is a lot easier than trying to connect after the initial setup. Enter the name of the network you want to connect to and then enter the password.
* At this point you will be asked to select an IP address for the device. It is recommended to select dhcp at this point.
* Now you will be asked if you want to do any manual network configuration. Unless you know what you're doing, press n and hit enter.
* You will now be asked to set a root password.
* You will now be asked to select a timezone.
* You will now be asked about a proxy URL. Type none or just hit enter.
* You will now be asked to choose a network time protocol client. Select busybox.
* Next you will be asked to choose an APK mirror. I recomment choosing the Edit /etc/apk/repositories with text editor option.
* If you choose that option the file will open with the vi text editor. Delete the current line with dd, and then press i to enter insert mode. Then enter the following links, press escape to return to normal mode, and enter :wq to save and quit the editor. 
```
http://dl-cdn.alpinelinux.org/alpine/v3.21/main
http://dl-cdn.alpinelinux.org/alpine/v3.21/community
```
* Now you will be asked to set up a user. Enter no.
* When asked to choose an SSH server, enter none.
* You will now be asked to choose a disk. If booting with only an sd card and no other drives it will say no disks are available and ask if you want to try boot media. Enter y.
* You will now see a list of available disks that should include your sd card, and a prompt asking you to enter the disk you want to use. Enter the name of the disk that is shown under Available disks.
* When asked how you want to use the disk, choose sys.
* You will now be asked if you want to erase the above disk and continue. Enter y.
* The system will now be installed on your selected disk.
* Reboot once the installation is complete.
* NOTE: If you added anything into a usercfg.txt file it will be overwritten after rebooting and you will need to add it to the sd card again.
* Now after booting the Pi again you should be prompted to login. You can login with root as the username and whatever root password you set earlier.
* You have now setup Alpine Linux on your Raspberry Pi

### Configuring the Pi as a wifi access point and adding the pilan service
* Install necessary packages:
```
apk add hostapd dnsmasq iptables
```
* Edit /etc/network/interfaces to the following:
```
auto lo
iface lo inet loopback

auto wlan0
iface wlan0 inet static
    address 192.168.100.1
    netmask 255.255.255.0
    
# auto eth0
# iface eth0 inet dhcp
```
* Restart networking to apply these changes: /etc/init.d/networking restart
* Will need to disable NTP for networking to restart, should probably just select none during setup
* Add networking and hostapd to default run level:
```
rc-update add networking default
rc-update add hostapd default
```
* Navigate to /etc/hostapd
```
cd /etc/hostapd
```
* Rename the file hostapd.conf to hostapd.conf.backup:
```
mv hostapd.conf hostapd.conf.backup
```
* Create and edit a new hostapd.conf file with the vi text editor:
```
vi hostapd.conf
```
* Enter insert mode with i and enter the following config:
```
interface=wlan0
driver=nl80211
ssid=pilan
hw_mode=g
channel=7
auth_algs=1
wpa=2
wpa_passphrase=securepassword
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
rsn_pairwise=CCMP
country=US
macaddr_acl=0
ignore_broadcast_ssid=0
wpa_group_rekey=86400
beacon_int=100
dtim_period=2
```
* In the above config, set ssid to whatever you want your access point to be named, set wpa_passphrase with the password you want to use to connect to it, and set country to your country code
* Save the file and exit vi by pressing escape, and then :wq
* At this point you also want to make sure that wpa_supplicant is not running and does not run automatically at boot, as this will interfere with the network interface booting into AP mode. Remove wpa_supplicant from run all run levels.
* Now we need to add the pilan service to the Alpine image. To do this, first shut down the pi, then remove the sd card and plug it back into the build machine. Then take the pilan-srvr executable (make sure it's compiled for ARM aarch64) and copy it to the sd card. It's path on the sd card should be /usr/local/bin/pilan-srvr
* Next, re-insert the sd card into the pi and boot. You should see the pilan-srvr executable at the above path.
* We now need to update the permissions of pilan-srvr. Navigate to /usr/local/bin and run:
```
chmod +x pilan-srvr
```
* Now we need to do some configuring to make the server run automatically at boot. Navigate to /etc/init.d and create a new file: pilan-srvr.
* Add this to the file:
```
#!/sbin/openrc-run
command=/usr/local/bin/pilan-srvr
command_args=""
pidfile=/var/run/pilan-srvr.pid
name=pilan-srvr
description="Secure wireless file storage"
```
* Now exit the file and make it executable with chmod +x pilan-srvr
* Next run rc-update add pilan-srvr default to add the pilan server to the default run level.
* You will also need to configure dnsmasq, otherwise other devices will probably not connect to the pi wifi. Create the file /etc/dnsmasq.conf and add:
```
interface=wlan0
dhcp-range=192.168.100.2,192.168.100.10,12h
```
* Next, run:
```
rc-update add dnsmasq default
/etc/init.d/dnsmasq start
```
* After rebooting, devices should be able to connect to the pi network.
* Now we need to add some folders to that the pilan service can run correctly. In the root directory, run:
```
mkdir data
cd data
mkdir logs
mkdir files
mkdir tmp
mkdir meta
mkdir mdk
```
* Make sure the pilan server is statically compiled.

TODO - access point now starts at boot. we now just need to add the pilan service and make that also start at boot, and then confirm that clients can connect and file transfers work, etc.
