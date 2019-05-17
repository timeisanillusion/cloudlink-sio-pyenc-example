# cloudlink-sio-pyenc-example

##Work-in-progress to demo removal a disk, encrypting and re-adding drive to ScaleIO
This should not be used for systems with data and existing ScaleIO volumes and is for demonstration perposes only
CloudLink Center and ScaleIO must already be setup
CloudLink REST API user must be pre-defined
ScaleIO Gateway must be accessible to process requests

##2 Files
###hostinfo.py
This is the main file which will take a list of nodes in a storage pool and convert the disks to being encrypted.


###settings.py
Holds various settings on the environment include login details and list of SDS nodes to encrypt
