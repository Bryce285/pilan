# pilan
Pilan is a program for wireless encrypted file storage over LAN. 

## Current Limitations and Issues
* UX: Currently, basic client-server communication works, and basic UPLOAD, DOWNLOAD, LIST, and DELETE commands have been implemented, however the UX is pretty rough.
* Key management: Pilan implements both encryption in transit and encryption at rest. The master device key is derived from a user passphrase, and is stored as an encrypted blob on disk. I think this provides acceptable key security for what this project is, however eventually I would like to add other key management techniques like key rotations.
* Setup: The use case that I have in mind for this project is that you could run something like Alpine Linux or a custom Linux image on a Raspberry Pi, set it up as a wifi access point, and then run the pilan server from the Pi. That can be pretty confusing and time consuming if you've never done that kind of thing before, but I'm working on a couple things to hopefully make it easier.
* Overall this project is in a very early/rough state, so there's a million things that would improve it. What I've listed here are just the top three general things that I'm working to improve right now. Once I get everything working a little smoother I'll update this readme with usage instructions.
