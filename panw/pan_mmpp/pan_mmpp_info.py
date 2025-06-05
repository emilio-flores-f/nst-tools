import xmltodict, requests, sys, time
from prettytable import PrettyTable
from getpass import getpass
from urllib3.exceptions import InsecureRequestWarning
from datetime import timedelta, datetime
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

host = sys.argv[1] # 10.3.100.14
api_key = sys.argv[2] # LUFRPT04SnJaK3QzVW1ZaCtYc2V0RlVheVdiSUVrL009UkNOUFpZZ04wWVBQMHBmanVDM3A4Q3dsQnhhN2g1S3M4R0V2cERlQWFuQS9HbmJhRnZPcE9LeGp3M1NQciswSQ==

def request_op_get(host,command,key):    
    request = xmltodict.parse(requests.get(f'https://{host}/api/?type=op&cmd={command}&key={key}', verify=False).content)
    if request['response']['@status'] == 'success':
        return(request['response']['result'])
    else:
        return('Request Error')

show_system_info = request_op_get(host,'<show><system><info/></system></show>',api_key)
if show_system_info == 'Request Error':
    print('[-] Error en la generación del request. Revise los parámetros e inténtelo nuevamente.')
else:
    if 'model' in show_system_info['system'].keys():
        if 'PA-' in show_system_info['system']['model']:
            device_type = 'firewall'
        else:
            if 'system-mode' in show_system_info['system'].keys():
                device_type = 'panorama'
            else:
                device_type = 'firewall'
    else:
        if 'system-mode' in show_system_info['system'].keys():
                device_type = 'panorama'
        else:
            device_type = 'firewall'
    pan_hostname = show_system_info['system']['hostname']
    pan_model = show_system_info['system']['model']
    pan_version = show_system_info['system']['sw-version']
    pan_ipaddress = show_system_info['system']['ip-address']
    pan_uptime = show_system_info['system']['uptime']
    if device_type == 'firewall':
        show_config_size = request_op_get(host,'<show><management-server><last-committed><config-size/></last-committed></management-server></show>',api_key)
        if show_config_size == 'Request Error':
            print('[-] Error en la generación del request. Revise los parámetros e inténtelo nuevamente.')
        else:
            config_size = round((int(show_config_size.split()[0])/1024),2)
    show_clock = request_op_get(host,'<show><clock/></show>',api_key)
    if show_clock == 'Request Error':
            print('[-] Error en la generación del request. Revise los parámetros e inténtelo nuevamente.')
    else:
        pan_time = show_clock
    print('\n')
    print('#'*100)
    print('System Info')
    print('#'*100)
    print(f"\nHostname: {pan_hostname}\nIP Address: {pan_ipaddress}\nModel: {pan_model}\nPanOS Version: {pan_version}\nUptime: {pan_uptime}\nClock: {pan_time}")
    if device_type == 'firewall':
        print(f"Config File Size: {config_size} kB\n")
    else:
        print('\n')
    print('#'*100)
    show_interfaces_all = request_op_get(host,'<show><interface>all</interface></show>',api_key)
    if show_interfaces_all == 'Request Error':
        print('[-] Error en la generación del request. Revise los parámetros e inténtelo nuevamente.')
    else:
        i = 0
        print('Interfaces')
        print('#'*100)
        if device_type == 'firewall':
            for interface in show_interfaces_all['hw']['entry']:
                if show_interfaces_all['hw']['entry'][i]['state'] == 'up':
                    if not 'loopback' in show_interfaces_all['hw']['entry'][i]['name'] and not 'tunnel' in show_interfaces_all['hw']['entry'][i]['name'] and not 'vlan' in show_interfaces_all['hw']['entry'][i]['name'] and 'ethernet' in show_interfaces_all['hw']['entry'][i]['name']:
                        show_interface_hw = request_op_get(host,'<show><interface>'+show_interfaces_all['hw']['entry'][i]['name']+'</interface></show>',api_key)
                        if show_interface_hw == 'Request Error':
                            print('[-] Error en la generación del request. Revise los parámetros e inténtelo nuevamente.')
                        else:
                            print(f"\n{show_interface_hw['hw']['name']}\n\tConfigured speed|duplex|state: {show_interface_hw['hw']['speed_c']}|{show_interface_hw['hw']['duplex_c']}|{show_interface_hw['hw']['state_c']}\n\tRuntime speed|duplex|state: {show_interface_hw['hw']['speed']}|{show_interface_hw['hw']['duplex']}|{show_interface_hw['hw']['state']}")
                            show_interface_hw = request_op_get(host,'<show><interface>'+show_interfaces_all['hw']['entry'][i]['name']+'</interface></show>',api_key)
                            if 'counters' in show_interface_hw['hw'].keys():
                                muestra1 = show_interface_hw['hw']['counters']['hw']['entry']['port']
                                time.sleep(5)
                                show_interface_hw = request_op_get(host,'<show><interface>'+show_interfaces_all['hw']['entry'][i]['name']+'</interface></show>',api_key)
                                muestra2 = show_interface_hw['hw']['counters']['hw']['entry']['port']
                                for k,v in muestra2.items():
                                    if 'rx' in k or 'tx' in k:
                                        print(f"\t{k} rate: {(int(v)-int(muestra1[k]))/5}/s")
                            else:
                                if 'ifnet' in show_interface_hw.keys():
                                    muestra1 = show_interface_hw['ifnet']['counters']['hw']['entry']['port']
                                    time.sleep(5)
                                    show_interface_hw = request_op_get(host,'<show><interface>'+show_interfaces_all['hw']['entry'][i]['name']+'</interface></show>',api_key)
                                    muestra2 = show_interface_hw['ifnet']['counters']['hw']['entry']['port']
                                    for k,v in muestra2.items():
                                        if 'rx' in k or 'tx' in k:
                                            print(f"\t{k} rate: {(int(v)-int(muestra1[k]))/5}/s")
                        i = i+1
                    else:
                        i = i+1
                else:
                    i = i+1
        else:
            show_interface_mgmt = request_op_get(host,'<show><interface>management</interface></show>',api_key)
            if show_interface_mgmt == 'Request Error':
                    print('[-] Error en la generación del request. Revise los parámetros e inténtelo nuevamente.')
            else:
                if show_interface_mgmt['info']['state'] == 'up':
                    print(f"\n{show_interface_mgmt['info']['name']}\n\tConfigured speed|duplex|state: {show_interface_mgmt['info']['speed_c']}|{show_interface_mgmt['info']['duplex_c']}|{show_interface_mgmt['info']['state_c']}\n\tRuntime speed|duplex|state: {show_interface_mgmt['info']['speed']}|{show_interface_mgmt['info']['duplex']}|{show_interface_mgmt['info']['state']}")
                    if 'counters' in show_interface_mgmt.keys():
                        muestra1 = show_interface_mgmt['counters']
                        time.sleep(5)
                        show_interface_mgmt = request_op_get(host,'<show><interface>management</interface></show>',api_key)
                        muestra2 = show_interface_mgmt['counters']
                        for k,v in muestra2.items():
                            if 'rx' in k or 'tx' in k:
                                print(f"\t{k} rate: {(int(v)-int(muestra1[k]))/5}/s")
        print('\n')
        print('#'*100)
        print('Disk')
        print('#'*100)
        print('\n')
        show_system_disk_space = request_op_get(host,'<show><system><disk-space/></system></show>',api_key)
        print(f'{show_system_disk_space}\n')
        print('#'*100)
        print('Processes')
        print('#'*100)
        print('\n')
        show_system_resources = request_op_get(host,'<show><system><resources/></system></show>',api_key)
        for line in show_system_resources.splitlines()[6:27]:
            print(line)
        print('\n')
        print('#'*100)
        print('MP CPU')
        print('#'*100)
        print('\n')
        for line in show_system_resources.splitlines():
            if '%Cpu(s)' in line:
                print(line)
        print('\n')
        print('#'*100)
        print('MP Memory')
        print('#'*100)
        print('\n')
        for line in show_system_resources.splitlines():
            if 'MiB Mem' in line:
                print(line)
        if device_type == 'firewall':
            print('\n')
            print('#'*100)
            print('DP CPU')
            print('#'*100)
            print('\n')
            show_running_resources = request_op_get(host,'<show><running><resource-monitor><day><last>7</last></day></resource-monitor></running></show>',api_key)
            for dp in show_running_resources['resource-monitor']['data-processors']:
                print('cpu-load-average')
                for core in show_running_resources['resource-monitor']['data-processors'][dp]['day']['cpu-load-average']['entry']:
                    print(f"\t{core}")
                print('\n')
                print('cpu-load-maximum')
                for core in show_running_resources['resource-monitor']['data-processors'][dp]['day']['cpu-load-maximum']['entry']:
                    print(f"\t{core}")
                print('\n')
                print('resource-utilization')
                for resource in show_running_resources['resource-monitor']['data-processors'][dp]['day']['resource-utilization']['entry']:
                    print(f"\t{resource}")
        print('\n')
        print('#'*100)
        print('HA')
        print('#'*100)
        print('\n')
        show_high_availability = request_op_get(host,'<show><high-availability><all/></high-availability></show>',api_key)
        if not show_high_availability == None:
            if show_high_availability == 'Request Error':
                print('[-] Error en la generación del request. Revise los parámetros e inténtelo nuevamente.')
            else:
                if show_high_availability['enabled'] == 'no':
                    print('HA Not Configured')
                else:
                    if device_type == 'firewall':
                        print(f"Mode: {show_high_availability['group']['mode']}\nLocal State: {show_high_availability['group']['local-info']['state']}\nSync State: {show_high_availability['group']['local-info']['state-sync']}\nPeer Connection: {show_high_availability['group']['peer-info']['conn-status']}\nPeer State: {show_high_availability['group']['peer-info']['state']}")
                    else:
                        if device_type == 'panorama':
                            print(f"Local State: {show_high_availability['local-info']['state']}\nPeer Connection: {show_high_availability['peer-info']['conn-status']}\nPeer State: {show_high_availability['peer-info']['state']}\nSync State: {show_high_availability['running-sync']}")
        if device_type == 'firewall':
            print('\n')
            print('#'*100)
            print('Panorama Status')
            print('#'*100)
            print('\n')
            show_panorama_status = request_op_get(host,'<show><panorama-status/></show>',api_key)
            if not show_panorama_status == None:
                if show_panorama_status == 'Request Error':
                    print('[-] Error en la generación del request. Revise los parámetros e inténtelo nuevamente.')
                else:
                    print(show_panorama_status)
            else:
                print('Panorama Not Configured\n')
        print('\n')
        print('#'*100)
        print('Licenses')
        print('#'*100)
        print('\n')
        request_license_info = request_op_get(host,'<request><license><info/></license></request>',api_key)
        if request_license_info == 'Request Error':
                print('[-] Error en la generación del request. Revise los parámetros e inténtelo nuevamente.')
        else:
            for entry in request_license_info['licenses']['entry']:
                print(f"\n{entry['feature']}\n\tIssued:  {entry['issued']}\n\tExpires: {entry['expires']}\n\tExpired: {entry['expired']}")
        print('\n')
        print('#'*100)
        print('Enviromentals')
        print('#'*100)
        print('\n')
        show_system_enviromentals = request_op_get(host,'<show><system><environmentals/></system></show>',api_key)
        if show_system_enviromentals == None:
            print("No information")
        else:
            if show_system_enviromentals == 'Request Error':
                    print('[-] Error en la generación del request. Revise los parámetros e inténtelo nuevamente.')
            else:
                for item,value in show_system_enviromentals.items():
                    print(item)
                    for slotk,slotv in value.items():
                        print(f"\t{slotk}")
                        for entryk,entryv in slotv.items():
                            if isinstance(entryv, list):
                                for entry in entryv:
                                    print(f"\t\t{entry['description']}, Alarm: {entry['alarm']}")
                            else:
                                print(f"\t\t{entryv['description']}, Alarm: {entryv['alarm']}")
        if device_type == 'panorama':
            print('\n')
            print('#'*100)
            print('Log Collector')
            print('#'*100)
            print('\n')
            show_log_collector_all = request_op_get(host,'<show><log-collector><all/></log-collector></show>',api_key)
            if show_log_collector_all == 'Request Error':
                print('[-] Error en la generación del request. Revise los parámetros e inténtelo nuevamente.')
            else:
                for collector in show_log_collector_all['log-collector']['entry']:
                    print(f"{collector['host-name']}\n\tConnected: {collector['connected']}\n\tConfig Status: {collector['config-status']}\n\tInter LC Status: {collector['interlc-status']}\n\tLogd: {collector['logd']}\n\tVldmgr: {collector['vldmgr']}\n\tVlds: {collector['vlds']}\n\tES: {collector['es']}")
                        
