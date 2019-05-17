#WORK IN PROCESS
#CloudLink and ScaleIO must already be deployed
#CloudLink API user account must exist and be defined in the settings.py file along with other connection information


#Import variables from settings.py
import settings
import json
from pprint import pprint
import requests
from requests.auth import HTTPBasicAuth
import time
import sys

from multiprocessing import Process


debug=settings.debug

#ScaleIO Token
token= "None"

#CloudLink Token
access_token="None"

#Settinngs
clcurl="https://" + settings.clc_ip + "/cloudlink/oauth/token"
siourl="https://"+settings.sio_ip+"/api/login"
protectionDomainId="0"
storagePoolId="0"
hosts=[]
done=0
total=100

#Get CloudLink Token
def clc_login():
    global access_token
    if access_token == "None":
        querystring = {"grant_type":"client_credentials", "client_id":settings.clc_username, "client_secret":settings.clc_password, "scope":"all"}
        headers = {'cache-control': "no-cache"}
        response = requests.request("POST", clcurl, headers=headers, params=querystring, verify=False)
        if debug : pprint (response.text)
        data = json.loads(response.text)
        access_token = data['access_token']
        access_token = 'Bearer '+access_token
        return access_token


def clc_logout():
    pprint("Logging out of CloudLink Center")
    global access_token
    querystring = {"grant_type":"client_credentials", "client_id":settings.clc_username, "client_secret":settings.clc_password, "scope":"all"}
    headers = {'cache-control': "no-cache"}
    url= "https://"+settings.clc_ip+"/cloudlink/rest/auth"
    response = requests.request("DELETE", clcurl, headers=headers, params=querystring, verify=False)
    if debug :pprint (response.text)

def progress(count, total, status=''):
    bar_len = 60
    filled_len = int(round(bar_len * count / float(total)))

    percents = round(100.0 * count / float(total), 1)
    bar = '=' * filled_len + '-' * (bar_len - filled_len)

    print('[%s] %s%s ...%s\r' % (bar, percents, '%', status))
    sys.stdout.flush() 


#Get ScaleIO Token
def sio_login():
    global token
    if token == "None":
        requests.packages.urllib3.disable_warnings()
        querystring = {"grant_type":"client_credentials","client_id":settings.sio_username,"client_secret":settings.sio_password,"scope":"all"}
        headers = {'cache-control': "no-cache"}
        response = requests.request("GET", siourl, headers=headers,auth=HTTPBasicAuth(settings.sio_username,settings.sio_password), verify=False)
        if debug : pprint(response.text)
        token = json.loads(response.text)
        return token

def sio_logout():
    global token
    pprint("Logging out of ScaleIO MDM")
    requests.packages.urllib3.disable_warnings()
    querystring = {"grant_type":"client_credentials","client_id":settings.sio_username,"client_secret":settings.sio_password,"scope":"all"}
    headers = {'cache-control': "no-cache"}
    url = "https://"+settings.sio_ip+"/api/logout"
    response = requests.request("GET", siourl, headers=headers,auth=HTTPBasicAuth(settings.sio_username,settings.sio_password), verify=False)
    if debug : pprint(response.text)




#Host class for storing hostname and disk info per host
class host(object):
    #A host with disk and encryption details
    def __init__(self):
        self.hostname = "" 
        self.disk = {} 
        self.disk_list=[]
        self.siouuid=""
        self.clcuuid=""
        self.ip=""
        self.sioname=""

    #Add a disk to an existing host
    def add_disk(self,clcdevid,clcmount,clclabel,status,disk_type,siodevid):
        new_disk={'clcdevid':clcdevid,'dev':clcmount,'encdev':clclabel, 'status':status,'disk_type':disk_type,'siodevid':siodevid}
        #print ("Added",new_disk['dev'])
        self.disk_list.append(new_disk)

    def display_hostname(self):
        print(self.hostname)
    
    #Return the disk status i.e. 'encrypted'/'encrypting'/'unencrypted' based on the CloudLink device ID
    def get_status_from_clcdev(clcdevid,clcuuid):
        for h in range(0,len(hosts)):
            if clcuuid==hosts[h].clcuuid:
                for i in range(0,len(hosts[h].disk_list)):
                    if hosts[h].disk_list[i]['clcdevid']==clcdevid:
                        if debug : pprint("Found Status Info for "+ hosts[h].ip +" : "+ hosts[h].disk_list[i]['dev'] +" : "+ hosts[h].disk_list[i]['status'])
                        return hosts[h].disk_list[i]['status']
        return 'unknown'

    #Return the disk status i.e. 'encrypted'/'encrypting'/'unencrypted' based on the ScaleIO device ID
    def get_status_from_siodev(siodevid):
        #pprint("Sent ScaleIO Dev ID : " +siodevid)
        if siodevid != "unkown":
            for h in range(0,len(hosts)):
                #pprint("Currently checking IP : " + hosts[h].ip + "for match")
                for i in range(0,len(hosts[h].disk_list)):
                    #pprint("Currently checking : " + hosts[h].disk_list[i]['siodevid'])
                    if hosts[h].disk_list[i]['siodevid']==siodevid:
                        if debug : pprint("Found Status Info for "+ hosts[h].disk_list[i]['dev'] +" : "+ hosts[h].disk_list[i]['status'])
                        return hosts[h].disk_list[i]['status']
            return 'unknown because device ID not found'
        else:
            return 'unknown sent unknown'

    #Return current encrypted path
    def get_encpath(clcdevid,clcuuid):
        for h in range(0,len(hosts)):
            if clcuuid==hosts[h].clcuuid:
                for i in range(0,len(hosts[h].disk_list)):
                    if hosts[h].disk_list[i]['clcdevid']==clcdevid:
                        pprint("Encryption Label Currently: "+ hosts[h].disk_list[i]['encdev'])
                        return hosts[h].disk_list[i]['encdev']
                
        return 'unknown'

    def get_path_from_clcdev(clcdevid,clcuuid):
        for h in range(0,len(hosts)):
            if clcuuid==hosts[h].clcuuid:
                for i in range(0,len(hosts[h].disk_list)):
                    if hosts[h].disk_list[i]['clcdevid']==clcdevid:
                        pprint("Device: "+ hosts[h].disk_list[i]['dev'])
                        return hosts[h].disk_list[i]['dev']
        return 'unknown'

    def get_path_from_siodev(siodevid):
        for h in range(0,len(hosts)):
            for i in range(0,len(hosts[h].disk_list)):
                if hosts[h].disk_list[i]['siodevid']==siodevid:
                    pprint("Device: "+ hosts[h].disk_list[i]['dev'])
                    return hosts[h].disk_list[i]['dev']
        return 'unknown'

    #find the host in the list that matches CloudLink host ID
    def find_position(clcuuid):
        #pprint("Sent : "+clcuuid)
        if clcuuid == "unknown":
            return -1

        else:
            #pprint("Looking for host "+clcuuid+" in known list.")
            for i in range(0,len(hosts)):
                if hosts[i].clcuuid == clcuuid:
                    if debug : pprint("found matching device with IP : "+hosts[i].ip)
                    return i
            pprint("No matching device found")
            return -1

    #find the host in the list that matches the ip
    def find_position_ip(ip):
        #pprint("**Looking for device with IP :"+ip)
        for i in range(0,len(hosts)):
            #pprint("Total Hosts : "+str(len(hosts)))
            #pprint("Checking Current Host : "+hosts[i].ip)
            if hosts[i].ip == ip:
                if debug : pprint("Found matching IP : "+hosts[i].ip)
                return i
        pprint("No matching IP found")
        return -1


    def find_position_siodevid(siodevid):

        if siodevid == "unknown":
            pprint("No ScaleIO Dev ID")
            return -1
        else:
            if debug : pprint("Looking for Host with SIO DevID: " +siodevid)
            for i in range(0,len(hosts)):
                for j in range(0,len(hosts[i].disk_list)):
                    if hosts[i].disk_list[j]['siodevid'] == siodevid:
                        if debug : pprint("found matching device on IP " +hosts[i].ip)
                        return i
            pprint("No matching device found")
            return -1

    def print_host_info():
         for h in range(0,len(hosts)):
            pprint("**************HOST*****************")
            pprint("Hostname : "+hosts[h].hostname)
            pprint("ScaleIO UID : "+hosts[h].siouuid)
            pprint("CloudLink UID : "+hosts[h].clcuuid)
            pprint("IP Address : "+hosts[h].ip)
            pprint("ScaleIO Node Name : "+hosts[h].sioname)
            pprint("*****Disk Info*****")
            for i in range(0,len(hosts[h].disk_list)):
                pprint("DISK #"+ str(i))
                pprint("CloudLink Dev ID : "+ hosts[h].disk_list[i]['clcdevid'])
                pprint("Mount Point : "+ hosts[h].disk_list[i]['dev'])
                pprint("Encrypted Mount : "+ hosts[h].disk_list[i]['encdev'])
                pprint("Current Status : "+ hosts[h].disk_list[i]['status'])
                pprint("Disk Type : "+ hosts[h].disk_list[i]['disk_type'])
                pprint("ScaleIO Dev ID : "+ hosts[h].disk_list[i]['siodevid'])





#Populate list of hosts and disk info from CloudLink
def getinfo_from_cloudlink():
    #Print Tokens
    if debug : print ("CloudLink Token : ",access_token)
    url = "https://"+settings.clc_ip+"/cloudlink/rest/securevm"
    #headers = {'cache-control': "no-cache"}
    #Retrieve Details
    headers = {'authorization': access_token, 'cache-control': "no-cache"}
    response = requests.request("GET", url, headers=headers, verify=False)
    if debug : pprint(response)
    data = json.loads(response.text)
    if debug : pprint(data)
    for i in range(0,len(data)):

        for z in range(0,len(settings.ip_list)):
            if settings.ip_list[z] == data[i].get('ip_address','XXX.XXX.XXX.XXX'):
                newhost=host()
                newhost.ip=data[i].get('ip_address',"None")
                newhost.clcuuid=data[i].get('uuid',"None")
                newhost.hostname=data[i].get('name',"None")
                resources=data[i].get('resources',"None")
                #for each disk on each host, collect useful data
                for j in range(0,len(resources)):
                    #Get info only if the disk is RAW or SIO
                    disk_type = resources[j].get('type',"None")
                    if (disk_type == "data_raw") or (disk_type == "data_sds"):
                        #print("Suitable Disk Found")
                        clcdevid=resources[j].get('id',"None")
                        clclabel=resources[j].get('label',"None")
                        clcstatus=resources[j].get('state',"None")
                        clcmount=resources[j].get('mpoint',"None")
                        #new_disk={'clcdevid':clcdevid,'dev':clcmount,'encdev':clclabel, 'status':clcstatus,'sio':disk_type}
                        if debug : pprint("New Disk Found"+clcmount)
                        newhost.add_disk(clcdevid,clcmount,clclabel,clcstatus,disk_type,"unknown")
                #add the completed object to the list
                pprint("Adding a host to list")
                hosts.append(newhost)



def getsio_PD_info():
    global protectionDomainId
    print ("ScaleIO Token : ",token)
    #Clear data before collecting new info
    headers = {'cache-control': "no-cache"}
    #URL for getting Protect Domain information from ScaleIO
    url = "https://"+settings.sio_ip+"/api/types/ProtectionDomain/instances"
    response = requests.request("GET", url, headers=headers,auth=HTTPBasicAuth('',token), verify=False)
    data = json.loads(response.text)
    if debug : pprint(data)
    for i in range(0,len(data)):
        if data[i].get('name') == settings.protection_domain:
            pprint("Found matching protection domain")
            protectionDomainId=data[i].get('id')



def getsio_SP_info():
    global storagePoolId
    pprint ("SP INFO")
    #Clear data before collecting new info
    headers = {'cache-control': "no-cache"}
    #URL for getting Protect Domain information from ScaleIO
    url = "https://"+settings.sio_ip+"/api/types/StoragePool/instances"
    response = requests.request("GET", url, headers=headers,auth=HTTPBasicAuth('',token), verify=False)
    data = json.loads(response.text)
    #print("Storage Pool Info Response")
    if debug : pprint(data)
    for i in range(0,len(data)):
        if data[i].get('name') == settings.storage_pool:
            storagePoolId=data[i].get('id')
            print("Found matching Storage Pool with ID : "+storagePoolId)


def getsio_sds_info():
    headers = {'cache-control': "no-cache"}
    #URL for getting SDS information from ScaleIO
    url = "https://"+settings.sio_ip+"/api/types/Sds/instances"
    response = requests.request("GET", url, headers=headers,auth=HTTPBasicAuth('',token), verify=False)
    data = json.loads(response.text)
    #for each item in response
    pprint ("SDS INFO")
    if debug : pprint(data)

    for i in range(0,len(data)):
        #read current SDSID and list of IPs
        cid = data[i].get('id')
        iplist = data[i].get('ipList')
        name = data[i].get('name')
        #pprint(iplist)
        #Search the list of a known CLC host
        for j in range(0,len(iplist)): 
            currentip=iplist[j].get('ip')
            for k in range(0,len(hosts)):
                #if IP matches record the SDSID
                if hosts[k].ip == currentip:
                    if debug : pprint("IP from hosts is :")
                    hosts[k].siouuid = cid
                    hosts[k].sioname = name
                    if debug : pprint("Found Matching IP : " + hosts[k].ip + "; SDS ID: " + hosts[k].siouuid)

def getsio_device_info():
    headers = {'cache-control': "no-cache"}
    #URL for getting SDS information from ScaleIO
    url = "https://"+settings.sio_ip+"/api/types/Device/instances"
    response = requests.request("GET", url, headers=headers,auth=HTTPBasicAuth('',token), verify=False)
    data = json.loads(response.text)
    #for each item in response
    pprint("Info from device_info request")
    if debug : pprint(data)
    for i in range(0,len(data)):
        #read current SDSID and list of IPs
        sdsID = data[i].get('sdsId')
        deviceOriginalPathName = data[i].get('deviceOriginalPathName')
        #deviceAlternativePath=deviceOriginalPathName[0:5]+deviceOriginalPathName[-3:]
        #pprint("Alt path is: "+deviceAlternativePath)
        #pprint(iplist)
        #Search udpate id for each know disk
        for j in range(0,len(hosts)):
            #Get the corrst host
            if sdsID == hosts[j].siouuid:
                for k in range(0,len(hosts[j].disk_list)):
                    if deviceOriginalPathName == hosts[j].disk_list[k]['dev'] or deviceOriginalPathName == hosts[j].disk_list[k]['encdev']:
                        hosts[j].disk_list[k]['siodevid']=data[i].get('id')
                        pprint("Adding SIO device ID"+data[i].get('id'))

def encrypt_device(clcuuid,clcdevid):
    
    update_clc_device_info(clcuuid)
    position=host.find_position(clcuuid)
    status=host.get_status_from_clcdev(clcdevid,clcuuid)


    pprint("Current Status : "+host.get_status_from_clcdev(clcdevid,clcuuid))

    if status != 'encrypted':
        pprint("Trying to encrypt device on:" +hosts[position].ip + " with device ID : "+clcdevid)
        url = "https://"+settings.clc_ip+"/cloudlink/rest/securevm/"+clcuuid+"/encryption/"+clcdevid
        headers = {'authorization': access_token, 'content-type': "application/json", 'cache-control': "no-cache"}
        payload = "{ \n\"encrypt\": \"encrypt\"\n}"
        response = requests.request("PUT", url, data=payload, headers=headers, verify=False)

        if (response.status_code == requests.codes.ok):
            pprint("Checking Encryption Status")
            time.sleep(5)
            update_clc_device_info(clcuuid)
            position=host.find_position(clcuuid)
            status=host.get_status_from_clcdev(clcdevid,clcuuid)          
            encpath=host.get_encpath(clcdevid,clcuuid)   
            if status != 'encrypted':
                pprint("Not yet encrypted, please wait")
                start= time.time()
                quit=False
                while (status != 'encrypted' and not quit):
                    pprint("Waiting for encryption to complete..")
                    time.sleep(5)
                    now=time.time()
                    elapsed=now-start
                    pprint("Checking for update..")
                    update_clc_device_info(clcuuid)        
                    status=host.get_status_from_clcdev(clcdevid,clcuuid)   
                    if elapsed > 45:
                        quit=True

            if status == 'encrypted':
                pprint("Device Encrypted")

        else:
            pprint("Something went wrong")



#NOT DONE
def update_sio_device_info(sdsid):
    #Find matching sio node
    pprint("!!!!!!!!!!!!!!!!!!Getting Device Information for ScaleIO ID: "+sdsid)
    for i in range(0,len(hosts)):
        if hosts[i].siouuid == sdsid:
            print ("ScaleIO Token : ",token)
            print("Send Value : "+sdsid)
            print("Found Value : "+hosts[i].siouuid)
            headers = {'cache-control': "no-cache"}
            #URL for getting SDS information from ScaleIO
            url = "https://"+settings.sio_ip+"/api/instances/Sds::"+sdsid+"/relationships/Device"
            pprint("URL : "+ url)
            response = requests.request("GET", url, headers=headers,auth=HTTPBasicAuth('',token), verify=False)
            data = json.loads(response.text)
            if debug : pprint(data)


def update_clc_device_info(clcid):
    pprint("Updating device info")
    position=host.find_position(clcid)
    if position > -1:
        if debug : print ("CloudLink Token : ",access_token)
        url = "https://"+settings.clc_ip+"/cloudlink/rest/securevm/"+clcid
        headers = {'authorization': access_token, 'cache-control': "no-cache"}
        response = requests.request("GET", url, headers=headers, verify=False)
        data = json.loads(response.text)
        resources=data.get('resources')
        if debug : pprint(resources)
        #Go through the list of drives returned
        for j in range(0,len(resources)):
            currentid=resources[j].get('id',"None")
            #Go through the list of know drives and update if matched
            for k in range(0,len(hosts[position].disk_list)):
                if currentid == hosts[position].disk_list[k]['clcdevid']:
                    if debug : pprint("Found matching disk updating status")
                    if debug : pprint("Status :" +resources[j].get('state',"None"))
                    hosts[position].disk_list[k]['status']=resources[j].get('state',"None")
                    hosts[position].disk_list[k]['dev']=resources[j].get('mpoint',"None")
                    hosts[position].disk_list[k]['encdev']=resources[j].get('label',"None")
        
    else:
        pprint("CLC Node not found")
                



def add_to_scaleio(sdsid,clclabel,PoolId):

    #Add to ScaleIO
    headers = {'content-type': "application/json", 'cache-control': "no-cache"}
    url = "https://"+settings.sio_ip+"/api/types/Device/instances"
    payload= "{\"sdsId\":\""+sdsid+"\",\"deviceCurrentPathname\":\""+clclabel+"\",\"storagePoolId\":\""+PoolId+"\"}"
    response = requests.request("POST", url, data=payload, headers=headers,auth=HTTPBasicAuth('',token), verify=False)
    data = json.loads(response.text)
    if debug : pprint(data)
    if debug : pprint(data.get('message','No feedback'))
    if data.get('errorCode','No feedback') != 562:
        pprint("Added to ScaleIO Pool")


def remove_from_scaleio(siodevid):

    #Check it's not encrypted (This will only remove unencrypted drives)

    #Get position in the list
    position=host.find_position_siodevid(siodevid)
    #Get status of the device
    status=host.get_status_from_siodev(siodevid)
    if status=="unencrypted":
        pprint("Device unencrypted")
        pprint("Removing device "+ siodevid +" from ScaleIO Pool")
        #Remove from ScaleIO Pool
        headers = {'content-type': "application/json", 'cache-control': "no-cache"}
        url = "https://"+settings.sio_ip+"/api/instances/Device::"+siodevid+"/action/removeDevice"
        payload= "{\n    \"force\":\"TRUE\"\n}"
        response = requests.request("POST", url, data=payload, headers=headers,auth=HTTPBasicAuth('',token), verify=False)
        data = json.loads(response.text)
        if debug : pprint(data)

        time.sleep(5)
        devstatus=check_sio_status(siodevid)
        start= time.time()
        quit=False
        #Wait until the device is no longer found (i.e. it's been removed)
        while (devstatus != 'not_in_sio' and not quit):
            pprint("Waiting for disk to remove.")
            time.sleep(15)
            now=time.time()
            elapsed=now-start
            pprint("Checking for update..")      
            devstatus=check_sio_status(siodevid)  
            if elapsed > 600:
                quit=True

    else:
        pprint("Not removing device, currently encrypted or not in ScaleIO")


def check_sio_status(siodevid):
    #Get position in the list
    position=host.find_position_siodevid(siodevid)
    #pprint("Cheching status for device on host with IP of : "+hosts[position].ip+ " and ScaleIO Device ID"+siodevid)
    #Get status of the device from ScaleIO
    headers = {'cache-control': "no-cache"}
    url = "https://"+settings.sio_ip+"/api/instances/Device::"+siodevid
    response = requests.request("GET", url, headers=headers,auth=HTTPBasicAuth('',token), verify=False)
    data = json.loads(response.text)
    if debug : pprint(data)
    #pprint("Device status from ScaleIO is : "+data.get('deviceState','not_in_sio'))
    return data.get('deviceState','not_in_sio')
            
        
def encrypt_sio_node(ip):
    global done
    position=host.find_position_ip(ip)
    pprint("************************Currently On IP: "+ip)

    #remove, encrypt the add each disk
    for i in range(0,len(hosts[position].disk_list)):
        #Each update should be for each disk on each node
        progresschunk=(100*(0.3/nodes)) / len(hosts[position].disk_list)
   
        done=done+progresschunk
        progress(done, total, status='Removing Disk From ScaleIO')

        pprint("************************Currently On disk: "+hosts[position].disk_list[i]['dev'])
        pprint("")
        pprint("******Checking for possible removal: "+hosts[position].disk_list[i]['dev']+" : "+hosts[position].ip)
        remove_from_scaleio(hosts[position].disk_list[i]['siodevid'])

        #Check device status
        devstatus=check_sio_status(hosts[position].disk_list[i]['siodevid'])
        pprint("Device status from ScaleIO is : "+devstatus)
        #Wait for the device to be in normal state
      
        #Start encryption
        done=done+progresschunk
        progress(done, total, status='Encrypting Disk')  
        if devstatus=='not_in_sio':
            pprint("")
            pprint("******Checking for possible encryption: "+hosts[position].disk_list[i]['dev']+" : "+hosts[position].ip)
            encrypt_device(hosts[position].clcuuid,hosts[position].disk_list[i]['clcdevid'])
        
          

        #Add to ScaleIO
        pprint("")
        pprint("******Checking for new encrypted device for ScaleIO: "+hosts[position].disk_list[i]['encdev']+" : "+hosts[position].ip)
        done=done+progresschunk
        progress(done, total, status='Adding to ScaleIO Pool')
        add_to_scaleio(hosts[position].siouuid, hosts[position].disk_list[i]['encdev'], storagePoolId)


#Main Workflow

#Get tokens
sio_login()
clc_login()

#Collect Device Info From CLC
getinfo_from_cloudlink()


#Collect Device Info From SIO
getsio_SP_info()
getsio_sds_info()
getsio_device_info()


#Update info for progress bar each node is (1/3)
nodes=len(hosts)
print(str(nodes))


#If debug is enabled, show a full list of all captured data
host.print_host_info()


#Start main process with full IP list
for i in range(0,len(settings.ip_list)):
    encrypt_sio_node(settings.ip_list[i])

clc_logout()
sio_logout()
progress(100, total, status='Done')