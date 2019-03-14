#coding=utf-8
import os
import json
import time
import datetime
import sys, getopt
import hashlib
import urllib

zstack_list = [#{'ip':"172.20.16.236", 'account':'admin', 'passwd':'Dw199719'}, 
               #{'ip':"172.20.16.236",'account':'admin', 'passwd':'password', 'name':'16.236'}, 
               {'ip':"172.20.1.15",'account':'admin', 'passwd':'password', 'name':'1.15'},
               {'ip':"172.20.0.10",'account':'admin', 'passwd':'ZStack%SHYZ_6#418', 'name':'云轴开发平台'}]

#aim_zstack = {'ip':"172.20.1.15",'account':'admin', 'passwd':'password', 'name':'1.15'}
aim_zstack = {'ip':"172.20.14.103",'account':'admin', 'passwd':'password', 'name':'14.103'}

def zql_generator(hypervisorType, zoneUuid):
    vm_conditions = "state='Running' and type='UserVm' and hypervisorType='%s'" % hypervisorType
    host_conditions = "hypervisorType='%s'" % hypervisorType
    if zoneUuid:
        vm_conditions += " and zoneUuid='%s'" % zoneUuid
        host_conditions += " and zoneUuid='%s'" % zoneUuid

    zql_dict = {
        #KVM_TOP5
        'vmCpuTop5': "query vminstance.uuid,name,cpuNum where %s return with (zwatch{resultName='CPUAllUsedUtilization',offsetAheadOfCurrentTime=1,metricName='CPUUsedUtilization',functions='average(groupBy=\"VMUuid\")', functions='top(num=5)'})" % vm_conditions,
        'vmMemTop5': "query vminstance.uuid,name,cpuNum where %s return with (zwatch{resultName='MemoryUsedInPercent',offsetAheadOfCurrentTime=1,metricName='MemoryUsedInPercent',functions='average(groupBy=\"VMUuid\")', functions='top(num=5)'})" % vm_conditions,
        'hostCpuTop5': "query host.uuid,name where %s return with (zwatch{resultName='CPUAllUsedUtilization',offsetAheadOfCurrentTime=1,metricName='CPUAllUsedUtilization',functions='average(groupBy=\"HostUuid\")', functions='top(num=5)'})" % host_conditions,
        'hostMemTop5': "query host.uuid,name where %s return with (zwatch{resultName='MemoryUsedInPercent',offsetAheadOfCurrentTime=1,metricName='MemoryUsedInPercent',functions='average(groupBy=\"HostUuid\")', functions='top(num=5)'})" % host_conditions,
        #KVM_VM_METRIC_DATA
        'vmCpuLoad': "query vminstance.uuid where %s return with(zwatch{resultName='cpuAllUsed',metricName='CPUAllUsedUtilization',offsetAheadOfCurrentTime=310,period=10})" % vm_conditions,
        'vmMemLoad': "query vminstance.uuid where %s return with(zwatch{resultName='memoryUsedBytes',metricName='MemoryUsedInPercent',offsetAheadOfCurrentTime=310,period=10})" % vm_conditions,
        'vmNetIn': "query vminstance.uuid where %s return with(zwatch{resultName='networkAllInBytes',metricName='NetworkAllInBytes',offsetAheadOfCurrentTime=310,period=10})" % vm_conditions,
        'vmNetOut': "query vminstance.uuid where %s return with(zwatch{resultName='networkAllOutBytes',metricName='NetworkAllOutBytes',offsetAheadOfCurrentTime=310,period=10})" % vm_conditions,
        'vmDiskWrite': "query vminstance.uuid where %s return with(zwatch{resultName='diskAllWriteBytes',metricName='DiskAllWriteBytes',offsetAheadOfCurrentTime=310,period=10})" % vm_conditions,
        'vmDiskRead': "query vminstance.uuid where %s return with(zwatch{resultName='diskAllReadBytes',metricName='DiskAllReadBytes',offsetAheadOfCurrentTime=310,period=10})" % vm_conditions,
        #KVM_HOST_METRIC_DATA
        'hostCpuLoad': "query host.uuid where %s return with(zwatch{resultName='cpuAllUsed',metricName='CPUAllUsedUtilization',offsetAheadOfCurrentTime=310,period=10})" % host_conditions,
        'hostMemLoad': "query host.uuid where %s return with(zwatch{resultName='memoryAllUsed',metricName='MemoryUsedInPercent',offsetAheadOfCurrentTime=310,period=10})" % host_conditions,
        'hostNetIn': "query host.uuid where %s return with(zwatch{resultName='networkAllInBytes',metricName='NetworkAllInBytes',offsetAheadOfCurrentTime=310,period=10})" % host_conditions,
        'hostNetOut': "query host.uuid where %s return with(zwatch{resultName='networkAllOutBytes',metricName='NetworkAllOutBytes',offsetAheadOfCurrentTime=310,period=10})" % host_conditions,
        'hostDiskWrite': "query host.uuid where %s return with(zwatch{resultName='diskAllWriteBytes',metricName='DiskAllWriteBytes',offsetAheadOfCurrentTime=310,period=10})" % host_conditions,
        'hostDiskRead': "query host.uuid where %s return with(zwatch{resultName='diskAllReadBytes',metricName='DiskAllReadBytes',offsetAheadOfCurrentTime=310,period=10})" % host_conditions,
        #ESX_TOP5
        'vcenterVmCpuTop5': "query vminstance.uuid,name,cpuNum where %s return with(zwatch{resultName='CPUAllUsedUtilization',namespace='ZStack/VCenter',offsetAheadOfCurrentTime=1,metricName='VmCPUUsage',functions='average(groupBy=\"VMUuid\")', functions='top(num=5)'})" % vm_conditions,
        'vcenterVmMemTop5': "query vminstance.uuid,name,cpuNum where %s return with(zwatch{resultName='MemoryUsedInPercent',namespace='ZStack/VCenter',offsetAheadOfCurrentTime=1,metricName='VmMemoryUsage',functions='average(groupBy=\"VMUuid\")', functions='top(num=5)'})" % vm_conditions,
        'vcenterHostCpuTop5': "query host.uuid,name where %s return with(zwatch{resultName='CPUAllUsedUtilization',namespace='ZStack/VCenter',offsetAheadOfCurrentTime=1,metricName='HostCPUUsage',functions='average(groupBy=\"HostUuid\")', functions='top(num=5)'})" % host_conditions,
        'vcenterHostMemTop5': "query host.uuid,name where %s return with(zwatch{resultName='MemoryUsedInPercent',namespace='ZStack/VCenter',offsetAheadOfCurrentTime=1,metricName='HostMemoryUsage',functions='average(groupBy=\"HostUuid\")', functions='top(num=5)'})" % host_conditions, 
        #ESX_VM_METRIC_DATA
        'vcenterVmCpuLoad': "query vminstance.uuid where %s return with(zwatch{resultName='cpuAllUsed',metricName='VmCPUUsage',namespace='ZStack/VCenter', offsetAheadOfCurrentTime=310,period=10})" % vm_conditions,
        'vcenterVmMemLoad': "query vminstance.uuid where %s return with(zwatch{resultName='memoryUsedBytes',metricName='VmMemoryUsage',namespace='ZStack/VCenter', offsetAheadOfCurrentTime=310,period=10})" % vm_conditions,
        'vcenterVmNetIn': "query vminstance.uuid where %s return with(zwatch{resultName='networkAllInBytes',metricName='VmNetworkReceived',namespace='ZStack/VCenter', offsetAheadOfCurrentTime=310,period=10})" % vm_conditions,
        'vcenterVmNetOut': "query vminstance.uuid where %s return with(zwatch{resultName='networkAllOutBytes',metricName='VmNetworkTransmitted',namespace='ZStack/VCenter', offsetAheadOfCurrentTime=310,period=10})" % vm_conditions,
        'vcenterVmDiskWrite': "query vminstance.uuid where %s return with(zwatch{resultName='diskAllWriteBytes',metricName='VmDiskWrite',namespace='ZStack/VCenter', offsetAheadOfCurrentTime=310,period=10})" % vm_conditions,
        'vcenterVmDiskRead': "query vminstance.uuid where %s return with(zwatch{resultName='diskAllReadBytes',metricName='VmDiskRead',namespace='ZStack/VCenter', offsetAheadOfCurrentTime=310,period=10})" % vm_conditions,
        #ESX_HOST_METRIC_DATA
        'vcenterHostCpuLoad': "query host.uuid where %s return with(zwatch{resultName='cpuAllUsed',metricName='HostCPUUsage',namespace='ZStack/VCenter',offsetAheadOfCurrentTime=310,period=10})" % host_conditions,
        'vcenterHostMemLoad': "query host.uuid where %s return with(zwatch{resultName='memoryAllUsed',metricName='HostMemoryUsage',namespace='ZStack/VCenter',offsetAheadOfCurrentTime=310,period=10})" % host_conditions,
        'vcenterHostNetIn': "query host.uuid where %s return with(zwatch{resultName='networkAllInBytes',metricName='HostNetworkReceived',namespace='ZStack/VCenter',offsetAheadOfCurrentTime=310,period=10})" % host_conditions,
        'vcenterHostNetOut': "query host.uuid where %s return with(zwatch{resultName='networkAllOutBytes',metricName='HostNetworkTransmitted',namespace='ZStack/VCenter',offsetAheadOfCurrentTime=310,period=10})" % host_conditions,
        'vcenterHostDiskWrite': "query host.uuid where %s return with(zwatch{resultName='diskAllWriteBytes',metricName='HostDiskWrite',namespace='ZStack/VCenter',offsetAheadOfCurrentTime=310,period=10})" % host_conditions,
        'vcenterHostDiskRead': "query host.uuid where %s return with(zwatch{resultName='diskAllReadBytes',metricName='HostDiskRead',namespace='ZStack/VCenter',offsetAheadOfCurrentTime=310,period=10})" % host_conditions,
    }
    return zql_dict

def login(zstack_ip, account='admin', passwd='password'):
    cmd = '''curl http://%s:8080/zstack/v1/accounts/login -X PUT -d \
          '{ "logInByAccount":{ \
             "password": "%s", \
             "accountName": "%s"}}' -s''' % (zstack_ip, hashlib.sha512(passwd).hexdigest(), account)
    authorization = json.loads(os.popen(cmd).read())
    return authorization

def logout(zstack_ip, session_uuid):
    cmd = ''' curl http://%s:8080/zstack/v1/accounts/sessions/%s -X DELETE -s''' % (zstack_ip, session_uuid)
    result = os.popen(cmd).read()
    return result

def query_zone(zstack_ip, session_uuid, uuid):
    cmd = ''' curl -H "Authorization: OAuth %s" \
              -X GET http://%s:8080/zstack/v1/zones/%s -s''' % (session_uuid, zstack_ip, uuid)
    result = json.loads(os.popen(cmd).read())
    return result

def query_cluster(zstack_ip, session_uuid, zone_uuid=None, hypervisorType='KVM'):
    cmd = ''' curl -H "Authorization: OAuth %s" \
              -X GET http://%s:8080/zstack/v1/clusters?q=hypervisorType=%s  -s''' % (session_uuid, zstack_ip, hypervisorType)
    if zone_uuid:
        cmd = ''' curl -H "Authorization: OAuth %s" \
              -X GET http://%s:8080/zstack/v1/clusters?q=hypervisorType=%s\&q=zoneUuid=%s  -s''' % (session_uuid, zstack_ip, hypervisorType, zone_uuid)
    result = json.loads(os.popen(cmd).read())
    return result

def query_vm(zstack_ip, session_uuid, zone_uuid=None, hypervisorType='KVM'):
    cmd = ''' curl -H "Authorization: OAuth %s" \
              -X GET http://%s:8080/zstack/v1/vm-instances?q=type=UserVm\&q=hypervisorType=%s\&q=state!=Destroyed\&q=state!=Expunging -s''' % (session_uuid, zstack_ip, hypervisorType)
    if zone_uuid:
        cmd = ''' curl -H "Authorization: OAuth %s" \
              -X GET http://%s:8080/zstack/v1/vm-instances?q=type=UserVm\&q=hypervisorType=%s\&q=state!=Destroyed\&q=state!=Expunging\&q=zoneUuid=%s -s''' % (session_uuid, zstack_ip, hypervisorType, zone_uuid)
    result = json.loads(os.popen(cmd).read())
    return result

def query_host(zstack_ip, session_uuid, uuids=None, zone_uuid=None, hypervisorType='KVM'):
    cmd = ''' curl -H "Authorization: OAuth %s" \
              -X GET http://%s:8080/zstack/v1/hosts?q=hypervisorType=%s  -s''' % (session_uuid, zstack_ip, hypervisorType)
    if zone_uuid:
        cmd = ''' curl -H "Authorization: OAuth %s" \
              -X GET http://%s:8080/zstack/v1/hosts?q=hypervisorType=%s\&q=zoneUuid=%s  -s''' % (session_uuid, zstack_ip, hypervisorType, zone_uuid)
    if uuids:
        cmd = ''' curl -H "Authorization: OAuth %s" \
              -X GET http://%s:8080/zstack/v1/hosts?q=uuid=%s -s''' % (session_uuid, zstack_ip, uuids)
    result = json.loads(os.popen(cmd).read())
    return result

def query_ps(zstack_ip, session_uuid, zone_uuid=None, cluster_type='zstack'):
    cmd = ''' curl -H "Authorization: OAuth %s" \
              -X GET http://%s:8080/zstack/v1/primary-storage?q=cluster.type=%s -s''' % (session_uuid, zstack_ip, cluster_type)
    if zone_uuid:
        cmd = ''' curl -H "Authorization: OAuth %s" \
              -X GET http://%s:8080/zstack/v1/primary-storage?q=cluster.type=%s\&q=zoneUuid=%s -s''' % (session_uuid, zstack_ip, cluster_type, zone_uuid)
    result = json.loads(os.popen(cmd).read())
    return result
    
def query_bs(zstack_ip, session_uuid, zone_uuid=None, vcenter=False):
    cmd = ''' curl -H "Authorization: OAuth %s" \
              -X GET http://%s:8080/zstack/v1/backup-storage?''' % (session_uuid, zstack_ip)
    if zone_uuid:
        cmd = ''' curl -H "Authorization: OAuth %s" \
              -X GET http://%s:8080/zstack/v1/backup-storage?q=attachedZoneUuids?=%s''' % (session_uuid, zstack_ip, zone_uuid)
    if vcenter:
        cmd = cmd + '\&q=type=VCenter -s'
    else:
        cmd = cmd + '\&q=type!=VCenter -s' 

    result = json.loads(os.popen(cmd).read())
    return result
    
def query_image(zstack_ip, session_uuid, zone_uuid=None, vcenter=False):
    cmd = ''' curl -H "Authorization: OAuth %s" \
              -X GET http://%s:8080/zstack/v1/images?q=system!=true\&q=__systemTag__!=remote''' % (session_uuid, zstack_ip)
    if zone_uuid:
        cmd = ''' curl -H "Authorization: OAuth %s" \
              -X GET http://%s:8080/zstack/v1/images?q=system!=true\&q=__systemTag__!=remote\&q=backupStorage.zone.uuid?=%s''' % (session_uuid, zstack_ip, zone_uuid)
    if vcenter:
        cmd = cmd + '\&q=format=vmtx -s'
    else:
        cmd = cmd + '\&q=format!=vmtx -s'
    result = json.loads(os.popen(cmd).read())
    return result

def query_host_cpu_mem_capacity(zstack_ip, session_uuid, cluster_uuids=None, host_uuids=None):
    cmd = ''' curl -H "Authorization: OAuth %s" \
                  -X GET http://%s:8080/zstack/v1/hosts/capacities/cpu-memory?all=true -s ''' % (session_uuid, zstack_ip)
    if cluster_uuids:
        cmd = ''' curl -H "Authorization: OAuth %s" \
                  -X GET http://%s:8080/zstack/v1/hosts/capacities/cpu-memory?clusterUuids=%s -s''' % (session_uuid, zstack_ip, cluster_uuids)
    elif host_uuids:
        cmd = ''' curl -H "Authorization: OAuth %s" \
                  -X GET http://%s:8080/zstack/v1/hosts/capacities/cpu-memory?hostUuids=%s -s''' % (session_uuid, zstack_ip, host_uuids)
    result = json.loads(os.popen(cmd).read())
    return result    

def query_memory_over_provision(zstack_ip, session_uuid):
    cmd = ''' curl -H "Authorization: OAuth %s" \
              -X GET http://%s:8080/zstack/v1/global-configurations?q=category=mevoco\&q=name=overProvisioning.memory -s''' % (session_uuid, zstack_ip)
    result = json.loads(os.popen(cmd).read())
    return result 

def query_cpu_over_provision(zstack_ip, session_uuid):
    cmd = ''' curl -H "Authorization: OAuth %s" \
              -X GET http://%s:8080/zstack/v1/global-configurations?q=category=host\&q=name=cpu.overProvisioning.ratio -s''' % (session_uuid, zstack_ip)
    result = json.loads(os.popen(cmd).read())
    return result 

def query_host_load(zstack_ip, session_uuid, name):
    cmd = ''' curl -H "Authorization: OAuth %s" \
              -X GET http://%s:8080/zstack/v1/zwatch/metrics?namespace=ZStack/Host\&metricName=%s -s''' % (session_uuid, zstack_ip, name)
    result = json.loads(os.popen(cmd).read())
    return result

def query_zql(zstack_ip, session_uuid, zql):
    cmd = ''' curl -H "Authorization: OAuth %s" \
              -X GET http://%s:8080/zstack/v1/zql?zql=%s -s''' % (session_uuid, zstack_ip, urllib.quote(zql))
    result = json.loads(os.popen(cmd).read())
    return result

def query_l3(zstack_ip, session_uuid, category=None, zone_uuid=None, ip_version=4, conditions=None):
    cmd = ''' curl -H "Authorization: OAuth %s" \
              -X GET http://%s:8080/zstack/v1/l3-networks -s''' % (session_uuid, zstack_ip)
    if category:
        cmd = ''' curl -H "Authorization: OAuth %s" \
              -X GET http://%s:8080/zstack/v1/l3-networks?q=category=%s\&q=ipVersion=%s\&q=system=false\&q=type=L3BasicNetwork%s -s''' % (session_uuid, zstack_ip, category, ip_version, conditions)
        if zone_uuid:
            cmd = ''' curl -H "Authorization: OAuth %s" \
              -X GET http://%s:8080/zstack/v1/l3-networks?q=category=%s\&q=ipVersion=%s\&q=system=false\&q=type=L3BasicNetwork\&q=zoneUuid=%s%s -s''' % (session_uuid, zstack_ip, category, ip_version, zone_uuid, conditions)
    result = json.loads(os.popen(cmd).read())
    return result

def query_ip_capacity(zstack_ip, session_uuid, l3_uuids=None):
    cmd = ''' curl -H "Authorization: OAuth %s" \
              -X GET http://%s:8080/zstack/v1/ip-capacity -s''' % (session_uuid, zstack_ip)
    if l3_uuids:
        cmd = ''' curl -H "Authorization: OAuth %s" \
              -X GET http://%s:8080/zstack/v1/ip-capacity?l3NetworkUuids=%s -s''' % (session_uuid, zstack_ip, l3_uuids)
    result = json.loads(os.popen(cmd).read())
    return result
        
def get_used_cpu_mem(host_list):
    used_cpu = 0
    used_mem = 0
    total_cpu = 0
    total_mem = 0
    for host in host_list:
        used_cpu += host['totalCpuCapacity'] - host['availableCpuCapacity']
        total_cpu += host['totalCpuCapacity']
        used_mem += host['totalMemoryCapacity'] - host['availableMemoryCapacity']
        total_mem += host['totalMemoryCapacity']
    return [used_cpu, total_cpu, used_mem, total_mem]

def get_used_ps(ps_list):
    used_ps = 0
    total_ps = 0
    for ps in ps_list:
        used_ps += ps['totalCapacity'] - ps['availableCapacity']
        total_ps += ps['totalCapacity']
    return [used_ps, total_ps]

def get_used_bs(bs_list):
    used_bs = 0
    total_bs = 0
    for bs in bs_list:
        used_bs += bs['totalCapacity'] - bs['availableCapacity']
        total_bs += bs['totalCapacity']
    return [used_bs, total_bs]

def get_used_ip(zstack_ip, session_uuid, l3_list):
    l3uuid = []
    used_ip = 0
    total_ip = 0
    if len(l3_list):
        for l3 in l3_list: l3uuid.append(str(l3['uuid']))
        ip_capacity = query_ip_capacity(zstack_ip, session_uuid, '\&l3NetworkUuids='.join(l3uuid))
        used_ip = ip_capacity['totalCapacity'] - ip_capacity['availableCapacity']
        total_ip = ip_capacity['totalCapacity']
    return [used_ip, total_ip]   

def get_value_sum_avg(data_list):
    value_sum = 0
    if len(data_list):
        for data in data_list:
            value_sum += data['value']
        return value_sum, round(value_sum, 2)/round(len(data_list), 2)
    else:
        return 0

def get_host_num(data_list):
    host_list = []
    for data in data_list:
        if data['labels']['HostUuid'] not in host_list: host_list.append(data['labels']['HostUuid'])
    return len(host_list)

def get_zone(zstack, uuid):
    session_uuid = login(zstack['ip'], account=zstack['account'], passwd=zstack['passwd'])['inventory']['uuid']
    try:
        zone = query_zone(zstack['ip'], session_uuid, uuid)['inventories']
    finally:
        logout(zstack['ip'], session_uuid)
    return zone

def get_buff_overview(mode, zone_uuid):
    #buff_init
    buff = {}
    #KVM
    buff['VM'] = {}
    buff['VM']['Running'] = 0
    buff['VM']['Stopped'] = 0
    buff['VM']['Other'] = 0
    buff['VM']['Sum'] = 0
    buff['Host'] = {}
    buff['Host']['Enabled'] = 0
    buff['Host']['Disabled'] = 0
    buff['Host']['Other'] = 0
    buff['Host']['Sum'] = 0
    buff['Image'] = {}
    buff['Image']['Enabled'] = 0
    buff['Image']['Disabled'] = 0
    buff['Image']['Other'] = 0
    buff['Image']['Sum'] = 0
    buff['Cluster'] = {}
    buff['Cluster']['Enabled'] = 0
    buff['Cluster']['Disabled'] = 0
    buff['Cluster']['Other'] = 0
    buff['Cluster']['Sum'] = 0
    #ESX
    buff['v_VM'] = {}
    buff['v_VM']['Running'] = 0
    buff['v_VM']['Stopped'] = 0
    buff['v_VM']['Other'] = 0
    buff['v_VM']['Sum'] = 0
    buff['v_Host'] = {}
    buff['v_Host']['Enabled'] = 0
    buff['v_Host']['Disabled'] = 0
    buff['v_Host']['Other'] = 0
    buff['v_Host']['Sum'] = 0
    buff['v_Image'] = {}
    buff['v_Image']['Enabled'] = 0
    buff['v_Image']['Disabled'] = 0
    buff['v_Image']['Other'] = 0
    buff['v_Image']['Sum'] = 0
    buff['v_Cluster'] = {}
    buff['v_Cluster']['Enabled'] = 0
    buff['v_Cluster']['Disabled'] = 0
    buff['v_Cluster']['Other'] = 0
    buff['v_Cluster']['Sum'] = 0

    def buff_generator(zstack, zone):
        session_uuid = login(zstack['ip'], account=zstack['account'], passwd=zstack['passwd'])['inventory']['uuid']
        try:
            if zone:
                #KVM
                vm_list = query_vm(zstack['ip'], session_uuid, zone_uuid=zone)['inventories']
                host_list = query_host(zstack['ip'], session_uuid, zone_uuid=zone)['inventories']
                image_list = query_image(zstack['ip'], session_uuid, zone_uuid=zone)['inventories']
                cluster_list = query_cluster(zstack['ip'], session_uuid, zone_uuid=zone)['inventories']
                #ESX
                v_vm_list = query_vm(zstack['ip'], session_uuid, zone_uuid=zone, hypervisorType='ESX')['inventories']
                v_host_list = query_host(zstack['ip'], session_uuid, zone_uuid=zone, hypervisorType='ESX')['inventories']
                v_image_list = query_image(zstack['ip'], session_uuid, zone_uuid=zone, vcenter=True)['inventories']
                v_cluster_list = query_cluster(zstack['ip'], session_uuid, zone_uuid=zone, hypervisorType='ESX')['inventories']
            else:
                #KVM
                vm_list = query_vm(zstack['ip'], session_uuid)['inventories']
                host_list = query_host(zstack['ip'], session_uuid)['inventories']
                image_list = query_image(zstack['ip'], session_uuid)['inventories']
                cluster_list = query_cluster(zstack['ip'], session_uuid)['inventories']
                #ESX
                v_vm_list = query_vm(zstack['ip'], session_uuid, hypervisorType='ESX')['inventories']
                v_host_list = query_host(zstack['ip'], session_uuid, hypervisorType='ESX')['inventories']
                v_image_list = query_image(zstack['ip'], session_uuid, vcenter=True)['inventories']
                v_cluster_list = query_cluster(zstack['ip'], session_uuid, hypervisorType='ESX')['inventories']
            #buff['VM']
            #KVM
            if len(vm_list):
                buff['VM']['Sum'] += len(vm_list)
                for vm in vm_list:    
                    if vm['state'] == 'Running': buff['VM']['Running'] += 1
                    elif vm['state'] == 'Stopped': buff['VM']['Stopped'] += 1
                    else: buff['VM']['Other'] += 1
            #ESX
            if len(vm_list):
                buff['v_VM']['Sum'] += len(v_vm_list)
                for vm in v_vm_list:    
                    if vm['state'] == 'Running': buff['v_VM']['Running'] += 1
                    elif vm['state'] == 'Stopped': buff['v_VM']['Stopped'] += 1
                    else: buff['v_VM']['Other'] += 1

            #buff['Host']
            #KVM
            if len(host_list):
                buff['Host']['Sum'] += len(host_list)
                for host in host_list:
                    if host['state'] == 'Enabled': buff['Host']['Enabled'] += 1
                    elif host['state'] == 'Disabled': buff['Host']['Disabled'] += 1
                    else: buff['Host']['Other'] += 1
            #ESX
            if len(host_list):
                buff['v_Host']['Sum'] += len(v_host_list)
                for host in v_host_list:
                    if host['state'] == 'Enabled': buff['v_Host']['Enabled'] += 1
                    elif host['state'] == 'Disabled': buff['v_Host']['Disabled'] += 1
                    else: buff['v_Host']['Other'] += 1

            #buff['Image']
            #KVM
            if len(image_list):
                buff['Image']['Sum'] += len(image_list)
                for image in image_list:
                    if image['state'] == 'Enabled': buff['Image']['Enabled'] += 1
                    elif image['state'] == 'Disabled': buff['Image']['Disabled'] += 1
                    else: buff['Image']['Other'] += 1
            #ESX
            if len(image_list):
                buff['v_Image']['Sum'] += len(v_image_list)
                for image in v_image_list:
                    if image['state'] == 'Enabled': buff['v_Image']['Enabled'] += 1
                    elif image['state'] == 'Disabled': buff['v_Image']['Disabled'] += 1
                    else: buff['v_Image']['Other'] += 1
            
            #buff['Cluster']
            #KVM
            if len(cluster_list):
                buff['Cluster']['Sum'] += len(cluster_list)
                for cluster in cluster_list:
                    if cluster['state'] == 'Enabled': buff['Cluster']['Enabled'] += 1
                    elif cluster['state'] == 'Disabled': buff['Cluster']['Disabled'] += 1
                    else: buff['Cluster']['Other'] += 1
            #ESX
            if len(cluster_list):
                buff['v_Cluster']['Sum'] += len(v_cluster_list)
                for cluster in v_cluster_list:
                    if cluster['state'] == 'Enabled': buff['v_Cluster']['Enabled'] += 1
                    elif cluster['state'] == 'Disabled': buff['v_Cluster']['Disabled'] += 1
                    else: buff['v_Cluster']['Other'] += 1
        finally:
            logout(zstack['ip'], session_uuid)
    if mode == 'all':
        for zstack in zstack_list:
            buff_generator(zstack, zone_uuid)        
    elif mode == 'single':
        buff_generator(aim_zstack, zone_uuid)
    return buff

def overview(mode='all', zone_uuid=None):
    buff_overview = get_buff_overview(mode, zone_uuid)
    #KVM
    print "--KVM资源总览--"
    print "-云主机\n 总数: %s\n 开机: %s\n 关机: %s\n 其他: %s\n" % (buff_overview['VM']['Sum'], buff_overview['VM']['Running'], buff_overview['VM']['Stopped'], buff_overview['VM']['Other'])
    print "-物理机\n 总数: %s\n 启用: %s\n 停用: %s\n 其他: %s\n" % (buff_overview['Host']['Sum'], buff_overview['Host']['Enabled'], buff_overview['Host']['Disabled'], buff_overview['Host']['Other'])
    print "-镜像\n 总数: %s\n 启用: %s\n 停用: %s\n 其他: %s\n" % (buff_overview['Image']['Sum'], buff_overview['Image']['Enabled'], buff_overview['Image']['Disabled'], buff_overview['Image']['Other'])
    if mode == 'single': print "-集群\n 总数: %s\n 启用: %s\n 停用: %s\n 其他: %s\n" % (buff_overview['Cluster']['Sum'], buff_overview['Cluster']['Enabled'], buff_overview['Cluster']['Disabled'], buff_overview['Cluster']['Other'])
    #ESX
    print "--VCenter资源总览--"
    print "-云主机\n 总数: %s\n 开机: %s\n 关机: %s\n 其他: %s\n" % (buff_overview['v_VM']['Sum'], buff_overview['v_VM']['Running'], buff_overview['v_VM']['Stopped'], buff_overview['v_VM']['Other'])
    print "-物理机\n 总数: %s\n 启用: %s\n 停用: %s\n 其他: %s\n" % (buff_overview['v_Host']['Sum'], buff_overview['v_Host']['Enabled'], buff_overview['v_Host']['Disabled'], buff_overview['v_Host']['Other'])
    print "-镜像\n 总数: %s\n 启用: %s\n 停用: %s\n 其他: %s\n" % (buff_overview['v_Image']['Sum'], buff_overview['v_Image']['Enabled'], buff_overview['v_Image']['Disabled'], buff_overview['v_Image']['Other'])
    if mode == 'single': print "-集群\n 总数: %s\n 启用: %s\n 停用: %s\n 其他: %s\n" % (buff_overview['v_Cluster']['Sum'], buff_overview['v_Cluster']['Enabled'], buff_overview['v_Cluster']['Disabled'], buff_overview['v_Cluster']['Other'])

def get_buff_rsu(mode, zone_uuid, avg):
    buff = {}
    #KVM
    buff['CPU'] = {}
    buff['MEM'] = {}
    buff['PS'] = {}
    buff['BS'] = {}
    buff['IP_pri_v4'] = {}
    buff['IP_pub_v4'] = {}
    buff['IP_pri_v6'] = {}
    buff['IP_pub_v6'] = {}
    buff['CPU']['sum'] = 0.00
    buff['MEM']['sum'] = 0.00
    buff['PS']['sum'] = 0.00
    buff['BS']['sum'] = 0.00
    buff['IP_pri_v4']['sum'] = 0.00
    buff['IP_pub_v4']['sum'] = 0.00
    buff['IP_pri_v6']['sum'] = 0.00
    buff['IP_pub_v6']['sum'] = 0.00
    sum_used_cpu = [0]
    sum_total_cpu = [0]
    sum_used_mem = [0]
    sum_total_mem = [0]   
    sum_used_ps = [0]
    sum_total_ps = [0]
    sum_used_bs = [0]
    sum_total_bs = [0]
    sum_used_pri_ip_v4 = [0]
    sum_total_pri_ip_v4 = [0]
    sum_used_pub_ip_v4 = [0]
    sum_total_pub_ip_v4 = [0]
    sum_used_pri_ip_v6 = [0]
    sum_total_pri_ip_v6 = [0]
    sum_used_pub_ip_v6 = [0]
    sum_total_pub_ip_v6 = [0]
    #ESX
    buff['v_CPU'] = {}
    buff['v_MEM'] = {}
    buff['v_PS'] = {}
    buff['v_BS'] = {}
    buff['v_IP_pri_v4'] = {}
    buff['v_IP_pub_v4'] = {}
    buff['v_IP_pri_v6'] = {}
    buff['v_IP_pub_v6'] = {}
    buff['v_CPU']['sum'] = 0.00
    buff['v_MEM']['sum'] = 0.00
    buff['v_PS']['sum'] = 0.00
    buff['v_BS']['sum'] = 0.00
    buff['v_IP_pri_v4']['sum'] = 0.00
    buff['v_IP_pub_v4']['sum'] = 0.00
    buff['v_IP_pri_v6']['sum'] = 0.00
    buff['v_IP_pub_v6']['sum'] = 0.00
    v_sum_used_cpu = [0]
    v_sum_total_cpu = [0]
    v_sum_used_mem = [0]
    v_sum_total_mem = [0]   
    v_sum_used_ps = [0]
    v_sum_total_ps = [0]
    v_sum_used_bs = [0]
    v_sum_total_bs = [0]
    v_sum_used_pri_ip_v4 = [0]
    v_sum_total_pri_ip_v4 = [0]
    v_sum_used_pub_ip_v4 = [0]
    v_sum_total_pub_ip_v4 = [0]
    v_sum_used_pri_ip_v6 = [0]
    v_sum_total_pri_ip_v6 = [0]
    v_sum_used_pub_ip_v6 = [0]
    v_sum_total_pub_ip_v6 = [0]
    def buff_generator(zstack, zone):
        session_uuid = login(zstack['ip'], account=zstack['account'], passwd=zstack['passwd'])['inventory']['uuid']
        try:
            #vcenter_l3_networks
            pri_l3_list_v4_vcenter = query_l3(zstack['ip'], session_uuid, category='Private', conditions='\&q=l2Network.cluster.type=vmware')['inventories']
            pub_l3_list_v4_vcenter = query_l3(zstack['ip'], session_uuid, category='Public', conditions='\&q=l2Network.cluster.type=vmware')['inventories']
            pri_l3_list_v6_vcenter = query_l3(zstack['ip'], session_uuid, category='Private', ip_version='6', conditions='\&q=l2Network.cluster.type=vmware')['inventories']
            pub_l3_list_v6_vcenter = query_l3(zstack['ip'], session_uuid, category='Public', ip_version='6', conditions='\&q=l2Network.cluster.type=vmware')['inventories']
            pri_l3_uuid_list_v4_vcenter = []
            pub_l3_uuid_list_v4_vcenter = []
            pri_l3_uuid_list_v6_vcenter = []
            pub_l3_uuid_list_v6_vcenter = []
            for l3 in pri_l3_list_v4_vcenter: pri_l3_uuid_list_v4_vcenter.append(str(l3['uuid']))
            for l3 in pub_l3_list_v4_vcenter: pub_l3_uuid_list_v4_vcenter.append(str(l3['uuid']))
            for l3 in pri_l3_list_v6_vcenter: pri_l3_uuid_list_v6_vcenter.append(str(l3['uuid']))
            for l3 in pub_l3_list_v6_vcenter: pub_l3_uuid_list_v6_vcenter.append(str(l3['uuid']))
            if zone:
                #KVM
                ps_list = query_ps(zstack['ip'], session_uuid, zone_uuid=zone)['inventories']
                bs_list = query_bs(zstack['ip'], session_uuid, zone_uuid=zone)['inventories']                
                pri_l3_list_v4 = query_l3(zstack['ip'], session_uuid, category='Private', zone_uuid=zone, conditions='\&q=uuid!?=%s' % ','.join(pri_l3_uuid_list_v4_vcenter))['inventories']
                pub_l3_list_v4 = query_l3(zstack['ip'], session_uuid, category='Public', zone_uuid=zone, conditions='\&q=uuid!?=%s' % ','.join(pub_l3_uuid_list_v4_vcenter))['inventories']
                pri_l3_list_v6 = query_l3(zstack['ip'], session_uuid, category='Private', zone_uuid=zone, ip_version='6', conditions='\&q=uuid!?=%s' % (','.join(pri_l3_uuid_list_v6_vcenter)))['inventories']
                pub_l3_list_v6 = query_l3(zstack['ip'], session_uuid, category='Public', zone_uuid=zone, ip_version='6', conditions='\&q=uuid!?=%s' % (','.join(pub_l3_uuid_list_v6_vcenter)))['inventories']
                cluster_list = query_cluster(zstack['ip'], session_uuid, zone_uuid=zone)['inventories']
                #ESX
                v_ps_list = query_ps(zstack['ip'], session_uuid, zone_uuid=zone, cluster_type='vmware')['inventories']
                v_bs_list = query_bs(zstack['ip'], session_uuid, zone_uuid=zone, vcenter=True)['inventories']
                v_cluster_list = query_cluster(zstack['ip'], session_uuid, zone_uuid=zone, hypervisorType='ESX')['inventories']
            else:
                #KVM       
                ps_list = query_ps(zstack['ip'], session_uuid)['inventories']
                bs_list = query_bs(zstack['ip'], session_uuid)['inventories']
                pri_l3_list_v4 = query_l3(zstack['ip'], session_uuid, category='Private', conditions='\&q=uuid!?=%s'% ','.join(pri_l3_uuid_list_v4_vcenter))['inventories']
                pub_l3_list_v4 = query_l3(zstack['ip'], session_uuid, category='Public', conditions='\&q=uuid!?=%s' % ','.join(pub_l3_uuid_list_v4_vcenter))['inventories']
                pri_l3_list_v6 = query_l3(zstack['ip'], session_uuid, category='Private', ip_version='6', conditions='\&q=uuid!?=%s' % (','.join(pri_l3_uuid_list_v6_vcenter)))['inventories']
                pub_l3_list_v6 = query_l3(zstack['ip'], session_uuid, category='Public', ip_version='6', conditions='\&q=uuid!?=%s' % (','.join(pub_l3_uuid_list_v6_vcenter)))['inventories']
                cluster_list = query_cluster(zstack['ip'], session_uuid)['inventories']
                #ESX
                v_ps_list = query_ps(zstack['ip'], session_uuid, cluster_type='vmware')['inventories']
                v_bs_list = query_bs(zstack['ip'], session_uuid, vcenter=True)['inventories']
                v_cluster_list = query_cluster(zstack['ip'], session_uuid, hypervisorType='ESX')['inventories']

            cluster_uuid_list = []
            for cluster in cluster_list: cluster_uuid_list.append(cluster['uuid'])
            cluster_uuids = '\&clusterUuids='.join(cluster_uuid_list)
            v_cluster_uuid_list = []
            for cluster in v_cluster_list: v_cluster_uuid_list.append(cluster['uuid'])
            v_cluster_uuids = '\&clusterUuids='.join(v_cluster_uuid_list)
            #rsu_list
            #KVM
            if cluster_uuids: 
                cpu_mem = query_host_cpu_mem_capacity(zstack['ip'], session_uuid, cluster_uuids=cluster_uuids)
            else:
                cpu_mem = {'totalCpu':0,'availableCpu':0,'totalMemory':0,'availableMemory':0}
            ps = get_used_ps(ps_list)
            bs = get_used_bs(bs_list)
            pri_v4 = get_used_ip(zstack['ip'], session_uuid, pri_l3_list_v4)
            pub_v4 = get_used_ip(zstack['ip'], session_uuid, pub_l3_list_v4)
            pri_v6 = get_used_ip(zstack['ip'], session_uuid, pri_l3_list_v6)
            pub_v6 = get_used_ip(zstack['ip'], session_uuid, pub_l3_list_v6)
            #ESX
            if v_cluster_uuids:
                v_cpu_mem = query_host_cpu_mem_capacity(zstack['ip'], session_uuid, cluster_uuids=v_cluster_uuids)
            else:
                v_cpu_mem = {'totalCpu':0,'availableCpu':0,'totalMemory':0,'availableMemory':0}
            v_ps = get_used_ps(v_ps_list)
            v_bs = get_used_bs(v_bs_list)
            v_pri_v4 = get_used_ip(zstack['ip'], session_uuid, pri_l3_list_v4_vcenter)
            v_pub_v4 = get_used_ip(zstack['ip'], session_uuid, pub_l3_list_v4_vcenter)
            v_pri_v6 = get_used_ip(zstack['ip'], session_uuid, pri_l3_list_v6_vcenter)
            v_pub_v6 = get_used_ip(zstack['ip'], session_uuid, pub_l3_list_v6_vcenter) 
            #init
            #KVM
            buff['CPU'][zstack['name']] = 0
            buff['MEM'][zstack['name']] = 0
            buff['PS'][zstack['name']] = 0
            buff['BS'][zstack['name']] = 0
            buff['IP_pri_v4'][zstack['name']] = 0
            buff['IP_pub_v4'][zstack['name']] = 0
            buff['IP_pri_v6'][zstack['name']] = 0
            buff['IP_pub_v6'][zstack['name']] = 0
            #ESX
            buff['v_CPU'][zstack['name']] = 0
            buff['v_MEM'][zstack['name']] = 0
            buff['v_PS'][zstack['name']] = 0
            buff['v_BS'][zstack['name']] = 0
            buff['v_IP_pri_v4'][zstack['name']] = 0
            buff['v_IP_pub_v4'][zstack['name']] = 0
            buff['v_IP_pri_v6'][zstack['name']] = 0
            buff['v_IP_pub_v6'][zstack['name']] = 0
            #KVM
            if cpu_mem['totalCpu']: buff['CPU'][zstack['name']] = round((float(cpu_mem['totalCpu'] - cpu_mem['availableCpu'])/float(cpu_mem['totalCpu'])) * 100, 2)
            if cpu_mem['totalMemory']: buff['MEM'][zstack['name']] = round((float(cpu_mem['totalMemory'] - cpu_mem['availableMemory'])/float(cpu_mem['totalMemory'])) * 100, 2)
            if ps[1]: buff['PS'][zstack['name']] = round((float(ps[0])/float(ps[1])) * 100, 2)
            if bs[1]: buff['BS'][zstack['name']] = round((float(bs[0])/float(bs[1])) * 100, 2)
            if pri_v4[1]: buff['IP_pri_v4'][zstack['name']] = round((float(pri_v4[0])/float(pri_v4[1])) * 100, 2)
            if pub_v4[1]: buff['IP_pub_v4'][zstack['name']] = round((float(pub_v4[0])/float(pub_v4[1])) * 100, 2)
            if pri_v6[1]: buff['IP_pri_v6'][zstack['name']] = round((float(pri_v6[0])/float(pri_v6[1])) * 100, 2)
            if pub_v6[1]: buff['IP_pub_v6'][zstack['name']] = round((float(pub_v6[0])/float(pub_v6[1])) * 100, 2)
            #ESX
            if v_cpu_mem['totalCpu']: buff['v_CPU'][zstack['name']] = round((float(v_cpu_mem['totalCpu'] - v_cpu_mem['availableCpu'])/float(v_cpu_mem['totalCpu'])) * 100, 2)
            if v_cpu_mem['totalMemory']: buff['v_MEM'][zstack['name']] = round((float(v_cpu_mem['totalMemory'] - v_cpu_mem['availableMemory'])/float(v_cpu_mem['totalMemory'])) * 100, 2)
            if v_ps[1]: buff['v_PS'][zstack['name']] = round((float(v_ps[0])/float(v_ps[1])) * 100, 2)
            if v_bs[1]: buff['v_BS'][zstack['name']] = round((float(v_bs[0])/float(v_bs[1])) * 100, 2)
            if v_pri_v4[1]: buff['v_IP_pri_v4'][zstack['name']] = round((float(v_pri_v4[0])/float(v_pri_v4[1])) * 100, 2)
            if v_pub_v4[1]: buff['v_IP_pub_v4'][zstack['name']] = round((float(v_pub_v4[0])/float(v_pub_v4[1])) * 100, 2)
            if v_pri_v6[1]: buff['v_IP_pri_v6'][zstack['name']] = round((float(v_pri_v6[0])/float(v_pri_v6[1])) * 100, 2)
            if v_pub_v6[1]: buff['v_IP_pub_v6'][zstack['name']] = round((float(v_pub_v6[0])/float(v_pub_v6[1])) * 100, 2)
            #KVM
            sum_used_cpu[0] += cpu_mem['totalCpu'] - cpu_mem['availableCpu']
            sum_total_cpu[0] += cpu_mem['totalCpu']
            sum_used_mem[0] += cpu_mem['totalMemory'] - cpu_mem['availableMemory']
            sum_total_mem[0] += cpu_mem['totalMemory']
            sum_used_ps[0] += ps[0]
            sum_total_ps[0] += ps[1]
            sum_used_bs[0] += bs[0]
            sum_total_bs[0] += bs[1]
            sum_used_pri_ip_v4[0] += pri_v4[0]
            sum_total_pri_ip_v4[0] += pri_v4[1]
            sum_used_pub_ip_v4[0] += pub_v4[0]
            sum_total_pub_ip_v4[0] += pub_v4[1]
            sum_used_pri_ip_v6[0] += pri_v6[0]
            sum_total_pri_ip_v6[0] += pri_v6[1]
            sum_used_pub_ip_v6[0] += pub_v6[0]
            sum_total_pub_ip_v6[0] += pub_v6[1]
            #ESX
            v_sum_used_cpu[0] += v_cpu_mem['totalCpu'] - v_cpu_mem['availableCpu']
            v_sum_total_cpu[0] += v_cpu_mem['totalCpu']
            v_sum_used_mem[0] += v_cpu_mem['totalMemory'] - v_cpu_mem['availableMemory']
            v_sum_total_mem[0] += v_cpu_mem['totalMemory']
            v_sum_used_ps[0] += v_ps[0]
            v_sum_total_ps[0] += v_ps[1]
            v_sum_used_bs[0] += v_bs[0]
            v_sum_total_bs[0] += v_bs[1]
            v_sum_used_pri_ip_v4[0] += v_pri_v4[0]
            v_sum_total_pri_ip_v4[0] += v_pri_v4[1]
            v_sum_used_pub_ip_v4[0] += v_pub_v4[0]
            v_sum_total_pub_ip_v4[0] += v_pub_v4[1]
            v_sum_used_pri_ip_v6[0] += v_pri_v6[0]
            v_sum_total_pri_ip_v6[0] += v_pri_v6[1]
            v_sum_used_pub_ip_v6[0] += v_pub_v6[0]
            v_sum_total_pub_ip_v6[0] += v_pub_v6[1]

        finally:
            logout(zstack['ip'],session_uuid)
        if avg == 'rsu':
            #KVM
            if sum_total_cpu[0]: buff['CPU']['sum'] = round((float(sum_used_cpu[0])/float(sum_total_cpu[0])) * 100, 2)
            if sum_total_mem[0]: buff['MEM']['sum'] = round((float(sum_used_mem[0])/float(sum_total_mem[0])) * 100, 2)
            if sum_total_ps[0]: buff['PS']['sum'] = round((float(sum_used_ps[0])/float(sum_total_ps[0])) * 100, 2)
            if sum_total_bs[0]: buff['BS']['sum'] = round((float(sum_used_bs[0])/float(sum_total_bs[0])) * 100, 2)
            if sum_total_pri_ip_v4[0]: buff['IP_pri_v4']['sum'] = round((float(sum_used_pri_ip_v4[0])/float(sum_total_pri_ip_v4[0])) * 100, 2)
            if sum_total_pub_ip_v4[0]: buff['IP_pub_v4']['sum'] = round((float(sum_used_pub_ip_v4[0])/float(sum_total_pub_ip_v4[0])) * 100, 2)
            if sum_total_pri_ip_v6[0]: buff['IP_pri_v6']['sum'] = round((float(sum_used_pri_ip_v6[0])/float(sum_total_pri_ip_v6[0])) * 100, 2)
            if sum_total_pub_ip_v6[0]: buff['IP_pub_v6']['sum'] = round((float(sum_used_pub_ip_v6[0])/float(sum_total_pub_ip_v6[0])) * 100, 2)
            #ESX
            if v_sum_total_cpu[0]: buff['v_CPU']['sum'] = round((float(v_sum_used_cpu[0])/float(v_sum_total_cpu[0])) * 100, 2)
            if v_sum_total_mem[0]: buff['v_MEM']['sum'] = round((float(v_sum_used_mem[0])/float(v_sum_total_mem[0])) * 100, 2)
            if v_sum_total_ps[0]: buff['v_PS']['sum'] = round((float(v_sum_used_ps[0])/float(v_sum_total_ps[0])) * 100, 2)
            if v_sum_total_bs[0]: buff['v_BS']['sum'] = round((float(v_sum_used_bs[0])/float(v_sum_total_bs[0])) * 100, 2)
            if v_sum_total_pri_ip_v4[0]: buff['v_IP_pri_v4']['sum'] = round((float(v_sum_used_pri_ip_v4[0])/float(v_sum_total_pri_ip_v4[0])) * 100, 2)
            if v_sum_total_pub_ip_v4[0]: buff['v_IP_pub_v4']['sum'] = round((float(v_sum_used_pub_ip_v4[0])/float(v_sum_total_pub_ip_v4[0])) * 100, 2)
            if v_sum_total_pri_ip_v6[0]: buff['v_IP_pri_v6']['sum'] = round((float(v_sum_used_pri_ip_v6[0])/float(v_sum_total_pri_ip_v6[0])) * 100, 2)
            if v_sum_total_pub_ip_v6[0]: buff['v_IP_pub_v6']['sum'] = round((float(v_sum_used_pub_ip_v6[0])/float(v_sum_total_pub_ip_v6[0])) * 100, 2)
        elif avg == 'percent':
            def sum_generator(dict):
                for k in dict.keys():
                    dict['sum'] += dict[k]
                dict['sum'] = round(float(dict['sum'])/float(len(dict.keys())-1), 2)
            for key in buff.keys():
                sum_generator(buff[key])            
    if mode == 'all':
        for zstack in zstack_list:
            buff_generator(zstack, zone_uuid)
    elif mode == 'single':
        buff_generator(aim_zstack, zone_uuid)
    return buff
    
def resource_used(mode='all', zone_uuid=None, avg='rsu'):
    #buff_rsu = get_buff_rsu(mode, zone_uuid)
    buff_rsu = get_buff_rsu(mode,zone_uuid,avg)
    #KVM
    print "--KVM用量统计--"
    print " CPU: %s%%\n 内存: %s%%\n 主存储: %s%%\n 镜像服务器: %s%%\n 私网IP_v4: %s%%\n 公网IP_v4: %s%%\n 私网IP_v6: %s%%\n 公网IP_v6: %s%% " % (buff_rsu['CPU']['sum'], \
        buff_rsu['MEM']['sum'], buff_rsu['PS']['sum'], buff_rsu['BS']['sum'], buff_rsu['IP_pri_v4']['sum'], buff_rsu['IP_pub_v4']['sum'], buff_rsu['IP_pri_v6']['sum'], buff_rsu['IP_pub_v6']['sum'])
    #ESX
    print "--VCenter用量统计--"
    print " CPU: %s%%\n 内存: %s%%\n 主存储: %s%%\n 镜像服务器: %s%%\n 私网IP_v4: %s%%\n 公网IP_v4: %s%%\n 私网IP_v6: %s%%\n 公网IP_v6: %s%% " % (buff_rsu['v_CPU']['sum'], \
        buff_rsu['v_MEM']['sum'], buff_rsu['v_PS']['sum'], buff_rsu['v_BS']['sum'], buff_rsu['v_IP_pri_v4']['sum'], buff_rsu['v_IP_pub_v4']['sum'], buff_rsu['v_IP_pri_v6']['sum'], buff_rsu['v_IP_pub_v6']['sum'])

def get_buff_host_load(mode):
    buff = {}
    buff['CPU'] = {}
    buff['MEM'] = {}
    buff['NI'] = {}
    buff['NO'] = {}
    buff['W'] = {}
    buff['R'] = {}
    def buff_generator(zstack):
        session_uuid = login(zstack['ip'], account=zstack['account'], passwd=zstack['passwd'])['inventory']['uuid']
        try:
            cpu = query_host_load(zstack['ip'], session_uuid, 'CPUAllUsedUtilization')['data']
            mem = query_host_load(zstack['ip'], session_uuid, 'MemoryUsedInPercent')['data']
            ni = query_host_load(zstack['ip'], session_uuid, 'NetworkAllInBytes')['data']
            no = query_host_load(zstack['ip'], session_uuid, 'NetworkAllOutBytes')['data']
            w = query_host_load(zstack['ip'], session_uuid, 'DiskAllWriteBytes')['data']
            i = query_host_load(zstack['ip'], session_uuid, 'DiskAllReadBytes')['data']
            host_num = get_host_num(cpu)
            div = round(len(cpu), 2)/round(host_num, 2)
            buff['CPU'][zstack['name']] = get_value_sum_avg(cpu)[1]
            buff['MEM'][zstack['name']] = get_value_sum_avg(mem)[1]
            buff['NI'][zstack['name']] = round(get_value_sum_avg(ni)[0], 2)/div
            buff['NO'][zstack['name']] = round(get_value_sum_avg(no)[0], 2)/div
            buff['W'][zstack['name']] = round(get_value_sum_avg(w)[0], 2)/div
            buff['R'][zstack['name']] = round(get_value_sum_avg(i)[0], 2)/div
        finally:
            logout(zstack['ip'], session_uuid)
    if mode == 'all':
        for zstack in zstack_list:
            buff_generator(zstack)
    if mode == 'single':
        buff_generator(aim_zstack)
    return buff

def postfix_div(num):
    p_d = {'postfix':'', 'div':1}
    if num >= 0 and num < 1024:
        p_d['postfix'] = 'B/s'
    elif num >= 1024 and num < 1024**2:
        p_d['postfix'] = 'KB/s'
        p_d['div'] = 1024
    elif num >= 1024**2 and num < 1024**3:
        p_d['postfix'] = 'MB/s'
        p_d['div'] = 1024**2
    else:
        p_d['postfix'] = 'GB/s'
        p_d['div'] = 1024**3
    return p_d

def print_topN(dict, mode = 'percent', max=5):
    count = 0
    for k in sorted(dict.items(), key=lambda item:item[1], reverse = True):
        if count >= max: break
        if mode == 'percent':
            postfix = '%'
            print " %s: %s %s" % (k[0], round(round(dict[k[0]], 2), 2), postfix)
        elif mode == 'Bytes':
            postfix = postfix_div(dict[k[0]])['postfix']
            div = postfix_div(dict[k[0]])['div']
            print " %s: %s %s" % (k[0], round(round(dict[k[0]], 2)/round(div, 2), 2), postfix)
            
def host_load(mode='all'):
    buff_hl = get_buff_host_load(mode)
    print "\n--负载统计--"
    print "-物理机CPU使用率:"
    print_topN(buff_hl['CPU'])
    print "\n-物理机内存使用率:"
    print_topN(buff_hl['MEM'])
    print "\n-物理机网络吞吐/接收:"
    print_topN(buff_hl['NI'], mode = 'Bytes')
    print "\n-物理机网络吞吐/发送:"
    print_topN(buff_hl['NO'], mode = 'Bytes')
    print "\n-物理机磁盘IO/写入:"
    print_topN(buff_hl['W'], mode = 'Bytes')
    print "\n-物理机磁盘IO/读取:"
    print_topN(buff_hl['R'], mode = 'Bytes')

def zstack_topN(mode='all', zone_uuid=None, avg='rsu'):
    buff_zstack = get_buff_rsu(mode, zone_uuid, avg)
    buff_zstack['CPU'].pop('sum')
    buff_zstack['MEM'].pop('sum')
    buff_zstack['PS'].pop('sum')
    print "\n--云平台TOP N"
    print "-CPU使用率:"
    print_topN(buff_zstack['CPU'])
    print "\n-内存使用率:"
    print_topN(buff_zstack['MEM'])
    print "\n-存储使用率:"
    print_topN(buff_zstack['PS'])

def get_buff_loads_top5(zone_uuid):
    #init
    buff = {}
    buff['vmCpuTop5'] = {}
    buff['vmMemTop5'] = {}
    buff['hostCpuTop5'] = {}
    buff['hostMemTop5'] = {}
    buff['v_vmCpuTop5'] = {}
    buff['v_vmMemTop5'] = {}
    buff['v_hostCpuTop5'] = {}
    buff['v_hostMemTop5'] = {}
    #generate
    session_uuid = login(aim_zstack['ip'], account=aim_zstack['account'], passwd=aim_zstack['passwd'])['inventory']['uuid']
    try:
        #KVM
        zql_dict = zql_generator('KVM', zone_uuid)
        buff['vmCpuTop5'] = query_zql(aim_zstack['ip'], session_uuid, zql_dict['vmCpuTop5'])['results'][0]
        buff['vmMemTop5'] = query_zql(aim_zstack['ip'], session_uuid, zql_dict['vmMemTop5'])['results'][0]
        buff['hostCpuTop5'] = query_zql(aim_zstack['ip'], session_uuid, zql_dict['hostCpuTop5'])['results'][0]
        buff['hostMemTop5'] = query_zql(aim_zstack['ip'], session_uuid, zql_dict['hostMemTop5'])['results'][0]
        #ESX
        v_zql_dict = zql_generator('ESX', zone_uuid)
        buff['v_vmCpuTop5'] = query_zql(aim_zstack['ip'], session_uuid, v_zql_dict['vcenterVmCpuTop5'])['results'][0]
        buff['v_vmMemTop5'] = query_zql(aim_zstack['ip'], session_uuid, v_zql_dict['vcenterVmMemTop5'])['results'][0]
        buff['v_hostCpuTop5'] = query_zql(aim_zstack['ip'], session_uuid, v_zql_dict['vcenterHostCpuTop5'])['results'][0]
        buff['v_hostMemTop5'] = query_zql(aim_zstack['ip'], session_uuid, v_zql_dict['vcenterHostMemTop5'])['results'][0]
        return buff
    finally:
        logout(aim_zstack['ip'], session_uuid)

def load_top5(zone_uuid=None):
    buff_loads = get_buff_loads_top5(zone_uuid)
    def print_name_value(inventories, resources, label):
        for resource in resources:
            for inventory in inventories:
                if resource['labels'][label] == inventory['uuid']:
                    value = round(resource['value'], 2) 
                    print " %s: %s %%" % (inventory['name'], round(value, 2))
                    break
    #KVM
    print "\n-KVM云主机CPU使用率TOP5-"
    if 'CPUAllUsedUtilization' in buff_loads['vmCpuTop5']['returnWith'].keys(): print_name_value(buff_loads['vmCpuTop5']['inventories'], buff_loads['vmCpuTop5']['returnWith']['CPUAllUsedUtilization'], 'VMUuid')
    print "\n-KVM云主机内存使用率TOP5-"
    if 'MemoryUsedInPercent' in buff_loads['vmMemTop5']['returnWith'].keys(): print_name_value(buff_loads['vmMemTop5']['inventories'], buff_loads['vmMemTop5']['returnWith']['MemoryUsedInPercent'], 'VMUuid')
    print "\n-KVM物理机CPU使用率TOP5-"
    if 'CPUAllUsedUtilization' in buff_loads['hostCpuTop5']['returnWith'].keys(): print_name_value(buff_loads['hostCpuTop5']['inventories'], buff_loads['hostCpuTop5']['returnWith']['CPUAllUsedUtilization'], 'HostUuid')
    print "\n-KVM物理机内存使用率TOP5-"
    if 'MemoryUsedInPercent' in buff_loads['hostMemTop5']['returnWith'].keys(): print_name_value(buff_loads['hostMemTop5']['inventories'], buff_loads['hostMemTop5']['returnWith']['MemoryUsedInPercent'], 'HostUuid')
    #ESX
    print "\n-VCenter云主机CPU使用率TOP5-"
    if 'CPUAllUsedUtilization' in buff_loads['v_vmCpuTop5']['returnWith'].keys(): print_name_value(buff_loads['v_vmCpuTop5']['inventories'], buff_loads['v_vmCpuTop5']['returnWith']['CPUAllUsedUtilization'], 'VMUuid')
    print "\n-VCenter云主机内存使用率TOP5-"
    if 'MemoryUsedInPercent' in buff_loads['v_vmMemTop5']['returnWith'].keys(): print_name_value(buff_loads['v_vmMemTop5']['inventories'], buff_loads['v_vmMemTop5']['returnWith']['MemoryUsedInPercent'], 'VMUuid')
    print "\n-VCenter物理机CPU使用率TOP5-"
    if 'CPUAllUsedUtilization' in buff_loads['v_hostCpuTop5']['returnWith'].keys(): print_name_value(buff_loads['v_hostCpuTop5']['inventories'], buff_loads['v_hostCpuTop5']['returnWith']['CPUAllUsedUtilization'], 'HostUuid')
    print "\n-VCenter物理机内存使用率TOP5-"
    if 'MemoryUsedInPercent' in buff_loads['v_hostMemTop5']['returnWith'].keys(): print_name_value(buff_loads['v_hostMemTop5']['inventories'], buff_loads['v_hostMemTop5']['returnWith']['MemoryUsedInPercent'], 'HostUuid')

def get_buff_host_metric_load(zone_uuid):
    #init
    buff = {}
    #KVM
    buff['CPU'] = {}
    buff['MEM'] = {}
    buff['NI'] = {}
    buff['NO'] = {}
    buff['W'] = {}
    buff['R'] = {}
    buff['CPU_VM'] = {}
    buff['MEM_VM'] = {}
    buff['NI_VM'] = {}
    buff['NO_VM'] = {}
    buff['W_VM'] = {}
    buff['R_VM'] = {}
    #ESX+
    buff['vCPU'] = {}
    buff['vMEM'] = {}
    buff['vNI'] = {}
    buff['vNO'] = {}
    buff['vW'] = {}
    buff['vR'] = {}
    buff['vCPU_VM'] = {}
    buff['vMEM_VM'] = {}
    buff['vNI_VM'] = {}
    buff['vNO_VM'] = {}
    buff['vW_VM'] = {}
    buff['vR_VM'] = {}
    def buff_generator(key, res_list, avg=True):
        host_num = round(len(res_list)/32, 2)
        for res in res_list:
            if res['time'] not in buff[key].keys():
                buff[key][res['time']] = 0
            if avg:
                buff[key][res['time']] += res['value']/host_num
            else:
                buff[key][res['time']] += res['value']
    #generate
    session_uuid = login(aim_zstack['ip'], account=aim_zstack['account'], passwd=aim_zstack['passwd'])['inventory']['uuid']
    try:
        #KVM
        zql_dict = zql_generator('KVM', zone_uuid)
        cpu = query_zql(aim_zstack['ip'], session_uuid, zql_dict['hostCpuLoad'])['results'][0]['returnWith']
        mem = query_zql(aim_zstack['ip'], session_uuid, zql_dict['hostMemLoad'])['results'][0]['returnWith']
        ni = query_zql(aim_zstack['ip'], session_uuid, zql_dict['hostNetIn'])['results'][0]['returnWith']
        no = query_zql(aim_zstack['ip'], session_uuid, zql_dict['hostNetOut'])['results'][0]['returnWith']
        w = query_zql(aim_zstack['ip'], session_uuid, zql_dict['hostDiskWrite'])['results'][0]['returnWith']
        r = query_zql(aim_zstack['ip'], session_uuid, zql_dict['hostDiskRead'])['results'][0]['returnWith']
        cpu_vm = query_zql(aim_zstack['ip'], session_uuid, zql_dict['vmCpuLoad'])['results'][0]['returnWith']
        mem_vm = query_zql(aim_zstack['ip'], session_uuid, zql_dict['vmMemLoad'])['results'][0]['returnWith']
        ni_vm = query_zql(aim_zstack['ip'], session_uuid, zql_dict['vmNetIn'])['results'][0]['returnWith']
        no_vm = query_zql(aim_zstack['ip'], session_uuid, zql_dict['vmNetOut'])['results'][0]['returnWith']
        w_vm = query_zql(aim_zstack['ip'], session_uuid, zql_dict['vmDiskWrite'])['results'][0]['returnWith']
        r_vm = query_zql(aim_zstack['ip'], session_uuid, zql_dict['vmDiskRead'])['results'][0]['returnWith']
        if 'cpuAllUsed' in cpu.keys(): 
            cpu_list = cpu['cpuAllUsed']
            buff_generator('CPU', cpu_list)
        if 'memoryAllUsed' in mem.keys(): 
            mem_list = mem['memoryAllUsed']
            buff_generator('MEM', mem_list)
        if 'networkAllInBytes' in ni.keys(): 
            ni_list = ni['networkAllInBytes']
            buff_generator('NI', ni_list, avg=False)
        if 'networkAllOutBytes' in no.keys(): 
            no_list = no['networkAllOutBytes']
            buff_generator('NO', no_list, avg=False)
        if 'diskAllWriteBytes' in w.keys(): 
            w_list = w['diskAllWriteBytes']
            buff_generator('W', w_list, avg=False)
        if 'diskAllReadBytes' in r.keys(): 
            r_list = r['diskAllReadBytes']
            buff_generator('R', r_list, avg=False)
        if 'cpuAllUsed' in cpu_vm.keys(): 
            cpu_list = cpu_vm['cpuAllUsed']
            buff_generator('CPU_VM', cpu_list)
        if 'memoryUsedBytes' in mem_vm.keys(): 
            mem_list = mem_vm['memoryUsedBytes']
            buff_generator('MEM_VM', mem_list)
        if 'networkAllInBytes' in ni_vm.keys(): 
            ni_list = ni_vm['networkAllInBytes']
            buff_generator('NI_VM', ni_list, avg=False)
        if 'networkAllOutBytes' in no_vm.keys(): 
            no_list = no_vm['networkAllOutBytes']
            buff_generator('NO_VM', no_list, avg=False)
        if 'diskAllWriteBytes' in w_vm.keys(): 
            w_list = w_vm['diskAllWriteBytes']
            buff_generator('W_VM', w_list, avg=False)
        if 'diskAllReadBytes' in r_vm.keys(): 
            r_list = r_vm['diskAllReadBytes']
            buff_generator('R_VM', r_list, avg=False)
        #ESX
        v_zql_dict = zql_generator('ESX', zone_uuid)
        v_cpu = query_zql(aim_zstack['ip'], session_uuid, v_zql_dict['vcenterHostCpuLoad'])['results'][0]['returnWith']
        v_mem = query_zql(aim_zstack['ip'], session_uuid, v_zql_dict['vcenterHostMemLoad'])['results'][0]['returnWith']
        v_ni = query_zql(aim_zstack['ip'], session_uuid, v_zql_dict['vcenterHostNetIn'])['results'][0]['returnWith']
        v_no = query_zql(aim_zstack['ip'], session_uuid, v_zql_dict['vcenterHostNetOut'])['results'][0]['returnWith']
        v_w = query_zql(aim_zstack['ip'], session_uuid, v_zql_dict['vcenterHostDiskWrite'])['results'][0]['returnWith']
        v_r = query_zql(aim_zstack['ip'], session_uuid, v_zql_dict['vcenterHostDiskRead'])['results'][0]['returnWith']
        v_cpu_vm = query_zql(aim_zstack['ip'], session_uuid, v_zql_dict['vcenterVmCpuLoad'])['results'][0]['returnWith']
        v_mem_vm = query_zql(aim_zstack['ip'], session_uuid, v_zql_dict['vcenterVmMemLoad'])['results'][0]['returnWith']
        v_ni_vm = query_zql(aim_zstack['ip'], session_uuid, v_zql_dict['vcenterVmNetIn'])['results'][0]['returnWith']
        v_no_vm = query_zql(aim_zstack['ip'], session_uuid, v_zql_dict['vcenterVmNetOut'])['results'][0]['returnWith']
        v_w_vm = query_zql(aim_zstack['ip'], session_uuid, v_zql_dict['vcenterVmDiskWrite'])['results'][0]['returnWith']
        v_r_vm = query_zql(aim_zstack['ip'], session_uuid, v_zql_dict['vcenterVmDiskRead'])['results'][0]['returnWith']

        if 'cpuAllUsed' in v_cpu.keys(): 
            v_cpu_list = v_cpu['cpuAllUsed']
            buff_generator('vCPU', v_cpu_list)
        if 'memoryAllUsed' in v_mem.keys(): 
            v_mem_list = v_mem['memoryAllUsed']
            buff_generator('vMEM', v_mem_list)
        if 'networkAllInBytes' in v_ni.keys(): 
            v_ni_list = v_ni['networkAllInBytes']
            buff_generator('vNI', v_ni_list, avg=False)
        if 'networkAllOutBytes' in v_no.keys(): 
            v_no_list = v_no['networkAllOutBytes']
            buff_generator('vNO', v_no_list, avg=False)
        if 'diskAllWriteBytes' in v_w.keys(): 
            v_w_list = v_w['diskAllWriteBytes']
            buff_generator('vW', v_w_list, avg=False)
        if 'diskAllReadBytes' in v_r.keys(): 
            v_r_list = v_r['diskAllReadBytes']
            buff_generator('vR', v_r_list, avg=False)
        if 'cpuAllUsed' in v_cpu_vm.keys(): 
            v_cpu_list = v_cpu_vm['cpuAllUsed']
            buff_generator('vCPU_VM', v_cpu_list)
        if 'memoryUsedBytes' in v_mem_vm.keys(): 
            v_mem_list = v_mem_vm['memoryUsedBytes']
            buff_generator('vMEM_VM', v_mem_list)
        if 'networkAllInBytes' in v_ni_vm.keys(): 
            v_ni_list = v_ni_vm['networkAllInBytes']
            buff_generator('vNI_VM', v_ni_list, avg=False)
        if 'networkAllOutBytes' in v_no_vm.keys(): 
            v_no_list = v_no_vm['networkAllOutBytes']
            buff_generator('vNO_VM', v_no_list, avg=False)
        if 'diskAllWriteBytes' in v_w_vm.keys(): 
            v_w_list = v_w_vm['diskAllWriteBytes']
            buff_generator('vW_VM', v_w_list, avg=False)
        if 'diskAllReadBytes' in v_r_vm.keys(): 
            v_r_list = v_r_vm['diskAllReadBytes']
            buff_generator('vR_VM', v_r_list, avg=False)
        return buff
    finally:
        logout(aim_zstack['ip'], session_uuid)

def host_metric_load(zone_uuid=None):
    buff_loads = get_buff_host_metric_load(zone_uuid)
    def print_time_value(buff, mode='percent'):
        k_list = buff.keys()
        k_list.sort()
        for k in k_list:
            k_time = datetime.datetime.fromtimestamp(k)
            if mode == 'percent':
                postfix = '%'
                print " %s: %s %s" % (k_time, round(round(buff[k], 2), 2), postfix)
            elif mode == 'Bytes':
                postfix = postfix_div(buff[k])['postfix']
                div = postfix_div(buff[k])['div']
                print " %s: %s %s" % (k_time, round(round(buff[k], 2)/round(div, 2), 2), postfix)
    #KVM
    print "\n--KVM负载统计--"
    print "-总物理机CPU使用率"
    print_time_value(buff_loads['CPU'])
    print "\n-总物理机内存使用率"
    print_time_value(buff_loads['MEM'])
    print "\n-总物理机网络吞吐/接收"
    print_time_value(buff_loads['NI'], mode='Bytes')
    print "\n-总物理机网络吞吐/发送"
    print_time_value(buff_loads['NO'], mode='Bytes')
    print "\n-总物理机磁盘IO/写入"
    print_time_value(buff_loads['W'], mode='Bytes')
    print "\n-总物理机磁盘IO/读取"
    print_time_value(buff_loads['R'], mode='Bytes')
    print "\n-总云主机CPU使用率"
    print_time_value(buff_loads['CPU_VM'])
    print "\n-总云主机内存使用率"
    print_time_value(buff_loads['MEM_VM'])
    print "\n-总云主机网络吞吐/接收"
    print_time_value(buff_loads['NI_VM'], mode='Bytes')
    print "\n-总云主机网络吞吐/发送"
    print_time_value(buff_loads['NO_VM'], mode='Bytes')
    print "\n-总云主机磁盘IO/写入"
    print_time_value(buff_loads['W_VM'], mode='Bytes')
    print "\n-总云主机磁盘IO/读取"
    print_time_value(buff_loads['R_VM'], mode='Bytes')
    #ESX
    print "\n--VCenter负载统计--"
    print "-总物理机CPU使用率"
    print_time_value(buff_loads['vCPU'])
    print "\n-总物理机内存使用率"
    print_time_value(buff_loads['vMEM'])
    print "\n-总物理机网络吞吐/接收"
    print_time_value(buff_loads['vNI'], mode='Bytes')
    print "\n-总物理机网络吞吐/发送"
    print_time_value(buff_loads['vNO'], mode='Bytes')
    print "\n-总物理机磁盘IO/写入"
    print_time_value(buff_loads['vW'], mode='Bytes')
    print "\n-总物理机磁盘IO/读取"
    print_time_value(buff_loads['vR'], mode='Bytes')
    print "\n-总云主机CPU使用率"
    print_time_value(buff_loads['vCPU_VM'])
    print "\n-总云主机内存使用率"
    print_time_value(buff_loads['vMEM_VM'])
    print "\n-总云主机网络吞吐/接收"
    print_time_value(buff_loads['vNI_VM'], mode='Bytes')
    print "\n-总云主机网络吞吐/发送"
    print_time_value(buff_loads['vNO_VM'], mode='Bytes')
    print "\n-总云主机磁盘IO/写入"
    print_time_value(buff_loads['vW_VM'], mode='Bytes')
    print "\n-总云主机磁盘IO/读取"
    print_time_value(buff_loads['vR_VM'], mode='Bytes')

def main(argv):
    try:
        opts, args = getopt.getopt(argv, "hasz:", [])
    except getopt.GetoptError:
        print 'python cmp.py -a \npython cmp.py -s \npython cmp.py -z <zone_uuid>'
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print 'python cmp.py -a \npython cmp.py -s \npython cmp.py -z <zone_uuid>'
            sys.exit()
        elif opt == '-a':
            print "---数据来源: ZStack总览---"
            #resource_overview
            overview()
            #resource_used
            resource_used(avg='percent')
            #host_load
            host_load()
            #zstack_topN
            zstack_topN()
        elif opt == '-s':
            print "---数据来源: %s 所有区域---" % aim_zstack['ip']
            #resource_overview
            overview(mode='single')
            #resource_used
            resource_used(mode='single')
            #host_load_metric_data
            host_metric_load()
            #top5
            load_top5()
        elif opt == '-z':
            zone_name = get_zone(aim_zstack, arg)[0]['name']
            print "---数据来源: %s 区域: %s---" % (aim_zstack['ip'], zone_name.encode("utf-8"))
            #resource_overview
            overview(mode='single', zone_uuid=arg)
            #resource_used
            resource_used(mode='single', zone_uuid=arg)
            #host_load_metric_data
            host_metric_load(arg)
            #top5
            load_top5(arg)

if __name__ == '__main__':
    main(sys.argv[1:])