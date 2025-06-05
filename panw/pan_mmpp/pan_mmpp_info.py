import xmltodict, requests, sys, time
from urllib3.exceptions import InsecureRequestWarning
from datetime import timedelta, datetime, timezone
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

host = sys.argv[1]
api_key = sys.argv[2]

def request_get(host,type,command,key):    
   request = xmltodict.parse(requests.get(f'https://{host}/api/?type={type}={command}&key={key}', verify=False).content)
   if request['response']['@status'] == 'success':
         return(request['response']['result'])
   else:
         return('Request Error')


def main():
   pa_images = [{'model':'PA-220','image':'https://www.paloguard.com.au/images/PA-Series/PA200-Series/PA220_FrontWtop.png'},
             {'model':'PA-850','image':'https://www.paloguard.com/images/PA-Series/PA850_FrontWtop.png'},
             {'model':'PA-3220','image':'https://www.paloguard.com/images/PA-Series/PA-3200-Series/pa-3220.jpg'},
             {'model':'PA-3250','image':'https://www.paloguard.com/images/PA-Series/PA-3200-Series/PA3250.jpg'},
             {'model':'PA-3260','image':'https://www.paloguard.com/images/PA-Series/PA-3200-Series/PA3260.jpg'},
             {'model':'PA-5220','image':'https://www.paloguard.com/images/PA-Series/PA5200/pa-5220-hero-l-440-196.jpg'},
             {'model':'PA-5250','image':'https://www.paloguard.com/images/PA-Series/PA5200/pa-5250-hero-l-440-196.jpg'},
             {'model':'PA-5260','image':'https://www.paloguard.com/images/PA-Series/PA5200/pa-5260-hero-l-440-196.jpg'},
             {'model':'PA-410','image':'https://www.paloguard.com/images/PA-Series/PA-400-Series/PA-410.png'},
             {'model':'PA-415','image':'https://www.paloguard.com/images/PA-Series/PA-400-Series/PA-415.png'},
             {'model':'PA-440','image':'https://www.paloguard.com/images/PA-Series/PA-400-Series/PA-440.png'},
             {'model':'PA-460','image':'https://www.paloguard.com/images/PA-Series/PA-400-Series/PA-460.png'},
             {'model':'PA-1410','image':'https://www.paloguard.com/images/PA-Series/PA1400/pa-1410.png'},
             {'model':'PA-1420','image':'https://www.paloguard.com/images/PA-Series/PA1400/pa-1420.png'},
             {'model':'PA-3410','image':'https://www.paloguard.com/images/PA-Series/pa-3400/pa3410.png'},
             {'model':'PA-3420','image':'https://www.paloguard.com/images/PA-Series/pa-3400/pa3420.png'},
             {'model':'PA-3430','image':'https://www.paloguard.com/images/PA-Series/pa-3400/pa3430.png'},
             {'model':'PA-3440','image':'https://www.paloguard.com/images/PA-Series/pa-3400/pa3440.png'},
             {'model':'PA-5410','image':'https://www.paloguard.com/images/PA-Series/pa-5400/5410.png'},
             {'model':'PA-5420','image':'https://www.paloguard.com/images/PA-Series/pa-5400/5420.png'},
             {'model':'PA-5430','image':'https://www.paloguard.com/images/PA-Series/pa-5400/Picture19.png'},
             {'model':'PA-5440','image':'https://www.paloguard.com/images/PA-Series/pa-5400/PA5440-Hero.png'},
             {'model':'PA-5445','image':'https://www.paloguard.com/images/PA-Series/pa-5400/PA5445-975X350.png'}
             ]
   
   html_file_name = f'reporte_{host}_{datetime.now().strftime("%d%m%Y_%H%M%S")}.html'

   system_info_list = {'hostname':'ND','model':'ND','sw-version':'ND','ip-address':'ND','uptime':'ND','serial':'ND','global-protect-client-package-version':'ND','app-version':'ND',
                       'app-release-date':'ND','av-version':'ND','av-release-date':'ND','threat-version':'ND','threat-release-date':'ND','wildfire-version':'ND',
                       'wildfire-release-date':'ND','multi-vsys':'ND'}
   sign_release_date_list = {'app-release-date':'ND','av-release-date':'ND','threat-release-date':'ND','wildfire-release-date':'ND'}
   
   show_system_info = request_get(host,'op&cmd','<show><system><info/></system></show>',api_key)
   print(f'[+] Requesting show_system_info')

   sign_release_html_table = ''
   if show_system_info == 'Request Error':
      print('[-] Error en la generación del request. Revise los parámetros e inténtelo nuevamente.')
   else:
      for sys_key, sys_value in system_info_list.items():
         if sys_key in show_system_info['system'].keys():
               system_info_list[sys_key] = show_system_info['system'][sys_key]
               for sig_key, sig_value in sign_release_date_list.items():
                  if sys_key == sig_key:
                     if sig_key == 'app-release-date':
                           if (datetime.now(timezone.utc) - datetime.strptime(f'{system_info_list[sys_key]}00','%Y/%m/%d %H:%M:%S %z')) < timedelta(days=30):
                              sig_value = 'OK'
                           else:
                              sig_value = 'NOK'
                     if sig_key == 'av-release-date' or sig_key == 'threat-release-date':
                           if (datetime.now(timezone.utc) - datetime.strptime(f'{system_info_list[sys_key]}00','%Y/%m/%d %H:%M:%S %z')) < timedelta(days=7):
                              sig_value = 'OK'
                           else:
                              sig_value = 'NOK'
                     if sig_key == 'wildfire-release-date':
                           if (datetime.now(timezone.utc) - datetime.strptime(f'{system_info_list[sys_key]}00','%Y/%m/%d %H:%M:%S %z')) < timedelta(days=1):
                              sig_value = 'OK'
                           else:
                              sig_value = 'NOK'
                     sign_release_html_template = f'  <tr> \
                                                      <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;" width="33.333333333333336%">{sys_key}</td> \
                                                      <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="33.333333333333336%">​{system_info_list[sys_key]}</br></td> \
                                                      <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="33.333333333333336%">​{sig_value}</td> \
                                                   </tr>'
                     sign_release_html_table = sign_release_html_table + sign_release_html_template
         else:
               None

      pan_image = 'https://upload.wikimedia.org/wikipedia/commons/thumb/d/de/PaloAltoNetworks_2020_Logo.svg/2560px-PaloAltoNetworks_2020_Logo.svg.png'
      for model in pa_images:
         if model['model'] == system_info_list['model']:
               pan_image = model['image']

      print(f'[+] Requesting show_preferred_version')
      panos_version_list = []
      panos_version_status = 'ND'
      show_preferred_version = request_get(host,'op&cmd','<request><system><software><check><preferred/></check></software></system></request>',api_key)
      if show_preferred_version == 'Request Error':
         show_preferred_version = 'ND'
         print('[-] Error en la generación del request show_preferred_version. Revise los parámetros e inténtelo nuevamente.')
      else:
         for entry in show_preferred_version['sw-updates']['versions']['entry']:
            panos_version_list.append(entry['version'])
      if system_info_list['sw-version'] in panos_version_list:
         panos_version_status = 'OK'
      else:
         panos_version_status = 'NOK'

      print(f'[+] Requesting show_config_size')
      show_config_size = request_get(host,'op&cmd','<show><management-server><last-committed><config-size/></last-committed></management-server></show>',api_key)
      if show_config_size == 'Request Error':
         pan_config_file_size = 'ND'
         print('[-] Error en la generación del request show_config_size. Revise los parámetros e inténtelo nuevamente.')
      else:
         pan_config_file_size = round((int(show_config_size.split()[0])/(1024)),2)
         if pan_config_file_size < 15360:
               pan_config_status_code = 'OK'
         else:
               pan_config_status_code = 'NOK'

      print(f'[+] Requesting show_clock')
      show_clock = request_get(host,'op&cmd','<show><clock/></show>',api_key)
      if show_clock == 'Request Error':
         pan_time = 'ND'
         pan_time_status = 'ND'
         print('[-] Error en la generación del request show_clock. Revise los parámetros e inténtelo nuevamente.')
      else:
         if len(show_clock.split()) == 6:
               pan_timezone_fix = show_clock.split()[4]+"00"
               pan_time = f'{" ".join(show_clock.split()[:4])} {pan_timezone_fix} {show_clock.split()[5]}'
               if (datetime.now(timezone.utc) - datetime.strptime(pan_time,'%a %b %d %H:%M:%S %z %Y')) < timedelta(minutes=5):
                  pan_time_status = 'OK'
               else: pan_time_status = 'NOK'
         else:
               pan_time = 'ND'
               pan_time_status = 'ND'
      
      print(f'[+] Requesting show_device_certificate')
      show_device_certificate = request_get(host,'op&cmd','<show><device-certificate><status></status></device-certificate></show>',api_key) #Needs admin privileges
      pan_device_cert_status = 'ND'
      pan_device_cert = 'ND'
      if show_device_certificate == 'Request Error':
         print('[-] Error en la generación del request show_device_certificate. Revise los parámetros e inténtelo nuevamente.')
      else:
         if 'validity' in show_device_certificate['device-certificate'].keys():
               pan_device_cert = show_device_certificate['device-certificate']['validity']
               if pan_device_cert == 'Valid':
                  pan_device_cert_status = 'OK'
               else:
                  pan_device_cert_status = 'NOK'
         else:
               if 'msg' in show_device_certificate['device-certificate'].keys():
                  pan_device_cert = show_device_certificate['device-certificate']['msg']
               else: pan_device_cert = 'ND'
               pan_device_cert_status = 'NOK'

      print(f'[+] Requesting show_system_software')
      show_system_software = request_get(host,'op&cmd','<show><system><software><status></status></software></system></show>',api_key)
      process_list_status = []
      if show_system_software == 'Request Error':
         system_software_status = 'ND'
         system_software_running = 'ND'
         print('[-] Error en la generación del request show_system_software. Revise los parámetros e inténtelo nuevamente.')
      else:
         for line in show_system_software.splitlines():
               if 'Group' in line or 'Process' in line:
                  if 'running' in line:
                     None
                  else:
                     process_list_status.append(line.split())
         if len(process_list_status) == 0:
               system_software_running = 'All Running'
               system_software_status = 'OK'
         else: 
               system_software_status = 'NOK'
               system_software_running = 'Not All Running'

      print(f'[+] Requesting show_system_enviromentals')
      show_system_enviromentals = request_get(host,'op&cmd','<show><system><environmentals/></system></show>',api_key)
      enviromental_status = 'ND'
      enviromental_item_alarm = 'ND'
      enviromental_alarms = []
      enviromental_items = []
      if show_system_enviromentals == None:
         enviromental_status = 'NA'
         enviromental_item_alarm = 'NA'
      else:
         if show_system_enviromentals == 'Request Error':
               print('[-] Error en la generación del request show_system_enviromentals. Revise los parámetros e inténtelo nuevamente.')
         else:
               for item,value in show_system_enviromentals.items():
                  for slotk,slotv in value.items():
                     item_slot_pair = f'{item}@{slotk}'
                     if not item_slot_pair in enviromental_items:
                           enviromental_items.append(item_slot_pair)
                     for entryk,entryv in slotv.items():
                           if isinstance(entryv, list):
                              for entry in entryv:
                                 if entry['alarm'] == 'True':
                                       enviromental_alarms.append(f"{entry['description']}, Alarm: {entry['alarm']}")
                           else:
                              if entryv['alarm'] == 'True':
                                 enviromental_alarms.append(f"{entryv['description']}, Alarm: {entryv['alarm']}")
               if len(enviromental_alarms) == 0:
                  enviromental_item_alarm = 'All false'
                  enviromental_status = 'OK'
               else: enviromental_status = 'NOK'

      print(f'[+] Requesting show_high_availability')
      show_high_availability = request_get(host,'op&cmd','<show><high-availability><all></all></high-availability></show>',api_key)
      pan_ha_status = 'ND'
      pan_ha_enabled = 'ND'
      pan_ha_mode = 'ND'
      pan_ha_compat = 'ND'
      pan_ha_sync_status = 'ND'
      pan_ha_local_state = 'ND'
      pan_ha_build_compat = 'ND'
      pan_ha_app_compat = 'ND'
      pan_ha_av_compat = 'ND'
      pan_ha_threat_compat = 'ND'
      pan_ha_running_sync = 'ND'
      if show_high_availability == 'Request Error':
         print('[-] Error en la generación del request show_high_availability. Revise los parámetros e inténtelo nuevamente.')
      else:
         if show_high_availability['enabled'] == 'yes':
               pan_ha_enabled = 'yes'
               pan_ha_mode = show_high_availability['group']['local-info']['mode']
               pan_ha_local_state = show_high_availability['group']['local-info']['state']
               pan_ha_build_compat = show_high_availability['group']['local-info']['build-compat']
               pan_ha_url_compat = show_high_availability['group']['local-info']['url-compat']
               pan_ha_app_compat = show_high_availability['group']['local-info']['app-compat']
               pan_ha_av_compat = show_high_availability['group']['local-info']['av-compat']
               pan_ha_threat_compat = show_high_availability['group']['local-info']['threat-compat']
               pan_ha_gpclient_compat = show_high_availability['group']['local-info']['gpclient-compat']
               pan_ha_running_sync = show_high_availability['group']['running-sync']
               if pan_ha_build_compat == 'Match' and pan_ha_app_compat == 'Match' and pan_ha_av_compat == 'Match' and pan_ha_threat_compat == 'Match':
                  pan_ha_compat = 'OK'
               else: pan_ha_compat = 'NOK'
               if pan_ha_running_sync == 'synchronized':
                  pan_ha_sync_status = 'OK'
               else: pan_ha_sync_status = 'NOK'
               if pan_ha_compat == 'OK' and pan_ha_sync_status == 'OK':
                  pan_ha_status == 'OK'
               else: pan_ha_status == 'NOK'
         else:
               pan_ha_build_compat = 'NA'
               pan_ha_app_compat = 'NA'
               pan_ha_av_compat = 'NA'
               pan_ha_threat_compat = 'NA'
               pan_ha_status = 'NA'
               pan_ha_enabled = 'NA'
               pan_ha_mode = 'NA'
               pan_ha_compat = 'NA'
               pan_ha_local_state = 'NA'
               pan_ha_sync_status = 'NA'

      print(f'[+] Requesting show_interface_mgmt')
      show_interface_mgmt = request_get(host,'op&cmd','<show><interface>management</interface></show>',api_key)
      mgmt_if_runtime_speed = 'ND'
      mgmt_if_runtime_duplex = 'ND'
      mgmt_if_runtime_status = 'ND'
      mgmt_if_err_drops = []
      mgmt_if_err_drops_status = 'ND'
      if show_interface_mgmt == 'Request Error':
            print('[-] Error en la generación del request show_interface_mgmt. Revise los parámetros e inténtelo nuevamente.')
      else:
         mgmt_if_hw_status = 'ND'
         mgmt_if_runtime_state = show_interface_mgmt['info']['state']
         mgmt_if_runtime_speed = show_interface_mgmt['info']['speed']
         mgmt_if_runtime_duplex = show_interface_mgmt['info']['duplex']
         mgmt_if_runtime_info = f'{mgmt_if_runtime_speed}/{mgmt_if_runtime_duplex}/{mgmt_if_runtime_state}'
         if mgmt_if_runtime_state == 'up' and mgmt_if_runtime_duplex == 'full':
               mgmt_if_runtime_status = 'OK'
         else: mgmt_if_runtime_status = 'NOK'
         if 'counters' in show_interface_mgmt.keys():
               muestra1 = show_interface_mgmt['counters']
               time.sleep(5)
               show_interface_mgmt = request_get(host,'op&cmd','<show><interface>management</interface></show>',api_key)
               muestra2 = show_interface_mgmt['counters']
               for k,v in muestra2.items():
                  if 'rx' in k or 'tx' in k:
                     if 'err' in k:
                           if not (int(v)-int(muestra1[k]))/5 == 0:
                              mgmt_if_err_drops.append(f"{k} rate: {(int(v)-int(muestra1[k]))/5}/s")
         if len(mgmt_if_err_drops) == 0:
               mgmt_if_err_drops_status = 'OK'
         else: 
               mgmt_if_err_drops_status = 'NOK'
         if mgmt_if_runtime_status == 'OK' and mgmt_if_err_drops_status == 'OK':
               mgmt_if_hw_status = 'OK'
         else:
               mgmt_if_hw_status = 'NOK'

      print(f'[+] Requesting show_interface_all')
      show_interface_all = request_get(host,'op&cmd','<show><interface>all</interface></show>',api_key)
      hw_ifs_html_table = ''
      if show_interface_all == 'Request Error':
            print('[-] Error en la generación del request show_interface_mgmt. Revise los parámetros e inténtelo nuevamente.')
      else:
         #print(show_interface_all)
         hw_if_counters_status = 'ND'
         hw_if_counters = 'ND'
         hw_if_runtime_status = 'ND'
         for hw_if_entry in show_interface_all['hw']['entry']:
               hw_if_status = 'ND'
               if hw_if_entry['type'] == '0' and hw_if_entry['state'] == 'up':
                  eth_if_err_counters = []
                  if_name = hw_if_entry['name']
                  if_runtime_state = hw_if_entry['st']
                  if if_runtime_state.split("/")[1] == 'full':
                     hw_if_runtime_status = 'OK'
                  else:
                     hw_if_runtime_status = 'NOK'
                  show_inferface_n = request_get(host,'op&cmd',f'<show><interface>{if_name}</interface></show>',api_key)
                  if show_inferface_n == 'Request Error':
                     print('[-] Error en la generación del request show_interface_mgmt. Revise los parámetros e inténtelo nuevamente.')
                  else:
                     if 'ifnet' in show_inferface_n.keys():
                           if 'counters' in show_inferface_n['ifnet']:
                              muestra1 = request_get(host,'op&cmd',f'<show><interface>{if_name}</interface></show>',api_key)['ifnet']['counters']
                              time.sleep(5)
                              muestra2 = request_get(host,'op&cmd',f'<show><interface>{if_name}</interface></show>',api_key)['ifnet']['counters']
                              for k,v in muestra2.items():
                                 if 'rx' in k or 'tx' in k:
                                       if 'err' in k:
                                          if not (int(v)-int(muestra1[k]))/5 == 0:
                                             eth_if_err_counters.append(f"{k} rate: {(int(v)-int(muestra1[k]))/5}/s")
                     else:
                           if 'counters' in show_inferface_n:
                              if 'hw' in show_inferface_n['counters']:
                                 if 'entry' in show_inferface_n['counters']['hw']:
                                       if 'port' in show_inferface_n['counters']['hw']['entry']:
                                          muestra1 = request_get(host,'op&cmd',f'<show><interface>{if_name}</interface></show>',api_key)['counters']['hw']['entry']['port']
                                          time.sleep(5)
                                          muestra2 = request_get(host,'op&cmd',f'<show><interface>{if_name}</interface></show>',api_key)['counters']['hw']['entry']['port']
                                          for k,v in muestra2.items():
                                             if 'err' in k:
                                                   if not (int(v)-int(muestra1[k]))/5 == 0:
                                                      eth_if_err_counters.append(f"{k} rate: {(int(v)-int(muestra1[k]))/5}/s")

                  if len(eth_if_err_counters) > 0:
                     hw_if_counters_status = 'NOK'
                     for counter in eth_if_err_counters:
                           hw_if_counters_html = f'<br>{counter}</br>'
                           hw_if_counters = hw_if_counters + hw_if_counters_html
                  else:
                     hw_if_counters = 0
                     hw_if_counters_status = 'OK'

                  if hw_if_runtime_status == 'OK' and hw_if_counters_status == "OK":
                     hw_if_status = "OK"
                  else:
                     hw_if_status = "NOK"
                  #print(if_name,hw_if_runtime_status,hw_if_counters_status)
                  hw_ifs_html_template = f'<tr>	\
                  <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;" width="33.333333333333336%"rowspan="2">{if_name}</td>	\
                  <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;" width="50%">Runtime Status​</td>	\
                  <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="50%">{if_runtime_state}​</td>	\
                  <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="33.333333333333336"rowspan="2">{hw_if_status}​</td>	\
                  </tr>	\
                  <tr>	\
                  <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;" width="50%">Error Counters​</td>	\
                  <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="50%">{hw_if_counters}​</td> 	\
                  </tr>'
                  hw_ifs_html_table = hw_ifs_html_table + hw_ifs_html_template

      print(f'[+] Requesting request_license_info')
      request_license_info = request_get(host,'op&cmd','<request><license><info/></license></request>',api_key)
      licenses = []
      licenses_html_table = ''
      if request_license_info == 'Request Error':
               print('[-] Error en la generación del request request_license_info. Revise los parámetros e inténtelo nuevamente.')
      else:
         if 'entry' in request_license_info['licenses'].keys():
               for entry in request_license_info['licenses']['entry']:
                  #licenses.append({'feature':,'issued':entry['issued'],'expires':,'expired':entry['expired']})
                  licenses.append({'feature':entry['feature'],'issued':entry['issued'],'expires':entry['expires'],'expired':entry['expired']})
                  if entry['expired'] == 'no':
                     entry_status = 'OK'
                  else: 
                     entry_status = 'NOK'
                  licenses_html_template = f'<tr> \
                  <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;" width="33.333333333333336%">{entry["feature"]}</td> \
                  <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="33.333333333333336%">{entry["expires"]}​</td> \
                  <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="33.333333333333336%">{entry_status}</td> \
                  </tr>'
                  licenses_html_table = licenses_html_table + licenses_html_template

      print(f'[+] Requesting show_panorama_status')
      show_panorama_status_status = 'ND'
      panorama_server = 'ND'
      panorama_connected = 'ND'
      panorama_servers_list = []
      panorama_connected_list = []
      panoramas_status = []
      panorama_html_table = ''
      show_panorama_status = request_get(host,'op&cmd','<show><panorama-status/></show>',api_key)
      if show_panorama_status == 'Request Error':
            print('[-] Error en la generación del request show_panorama_status. Revise los parámetros e inténtelo nuevamente.')
      else:
         if show_panorama_status == None:
               show_panorama_status_status = 'NA'
               panorama_html_table = f'<tr> \
                  <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;" width="33.333333333333336%">N/A</td> \
                  <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="33.333333333333336%">N/A​</td> \
                  <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="33.333333333333336%">N/A​</td> \
                  </tr>'
         else:
               for line in show_panorama_status.splitlines():
                  if 'Panorama Server' in line:
                     if len(line.split(":")[-1]):
                           panorama_server = line.split(":")[-1]
                           panorama_servers_list.append(panorama_server)
                  if 'Connected' in line:
                     if 'yes' in line or 'no' in line:
                           panorama_connected = line.split(":")[-1].strip()
                           panorama_connected_list.append(panorama_connected)
      i = 0
      if len(panorama_servers_list) == len(panorama_connected_list):
         for panorama in panorama_servers_list:
               panorama_i = {'panorama_server':panorama,'panorama_connected':panorama_connected_list[i]}
               panoramas_status.append(panorama_i)
               i = i+1
         for panorama in panoramas_status:
               if panorama['panorama_connected'] == 'yes':
                  show_panorama_status_status = 'OK'
               else:
                  show_panorama_status_status = 'NOK'
               panorama_html_template = f'<tr> \
               <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;" width="33.333333333333336%">{panorama["panorama_server"]}</td> \
               <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="33.333333333333336%">{panorama["panorama_connected"]}​</td> \
               <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="33.333333333333336%">{show_panorama_status_status}​</td> \
               </tr>'
               panorama_html_table = panorama_html_table + panorama_html_template
      else:
         panorama_html_table = f'<tr> \
               <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;" width="33.333333333333336%">N/A</td> \
               <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="33.333333333333336%">N/A​</td> \
               <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="33.333333333333336%">N/A​</td> \
               </tr>'

      print(f'[+] Requesting show_system_resources')
      show_system_resources = request_get(host,'op&cmd','<show><system><resources/></system></show>',api_key)
      mp_cpu_us = 'ND'
      mp_cpu_us_status = 'ND'
      mp_mem_us = 'ND'
      mp_mem_us_status = 'ND'
      if show_system_resources == 'Request Error':
            print('[-] Error en la generación del request show_system_resources. Revise los parámetros e inténtelo nuevamente.')
      else:
         for line in show_system_resources.splitlines():
               if '%Cpu(s):' in line:
                  if len(line.split()) == 17:
                     mp_cpu_us = round(float(line.split()[1]))
                     mp_cpu_us_str = line.split()[1] + "%"
               if 'MiB Mem :' in line:
                  if len(line.split()) == 11:
                     mp_mem_total = float(line.split()[3])
                     mp_mem_used = float(line.split()[7])
                     if mp_mem_total > mp_mem_used:
                           mp_mem_us = round(mp_mem_used*100/mp_mem_total)
                           mp_mem_us_str = str(mp_mem_us) + "%"
      if mp_cpu_us > 80:
         mp_cpu_us_status = 'NOK'
      else:
         mp_cpu_us_status = 'OK'
      if mp_mem_us > 80:
         mp_mem_us_status = 'NOK'
      else:
         mp_mem_us_status = 'OK'


      print(f'[+] Requesting show_system_disk_space')
      disk_use = 'ND'
      disk_part_list = []
      dis_use_html_table = ''
      disk_use_status = 'ND'
      show_system_disk_space = request_get(host,'op&cmd','<show><system><disk-space/></system></show>',api_key)
      if show_system_disk_space == 'Request Error':
            print('[-] Error en la generación del request show_system_disk_space. Revise los parámetros e inténtelo nuevamente.')
      else:
            for line in show_system_disk_space.splitlines():
               if len(line.split()) == 6 and not 'Filesystem' in line:
                  disk_mounted_on = line.split()[5]
                  disk_use = int(line.split()[4].replace("%",""))
                  disk_dict = {'disk_mounted_on':disk_mounted_on,'disk_use':disk_use}
                  disk_part_list.append(disk_dict)
      if len(disk_part_list) > 0:
         q_part_disk = f'{str(len(disk_part_list))}'
         dis_use_html_table_tmp = ''
         disk_part_status_list = []
         for part in disk_part_list:
               if part['disk_use'] > 80:
                  disk_part_status_list.append({'disk_mounted_on':part['disk_mounted_on'],'disk_part_status':'NOK'})
               else:
                  disk_part_status_list.append({'disk_mounted_on':part['disk_mounted_on'],'disk_part_status':'OK'})
         disk_use_status = 'OK'
         for part in disk_part_status_list:
               if 'NOK' in part['disk_part_status']:
                  disk_use_status = 'NOK'
         dis_use_html_table_tmp1 = ''
         for part in disk_part_list[1:]:
               part_name = part["disk_mounted_on"]
               part_use = str(part["disk_use"]) + "%"
               dis_use_html_template = f'  <tr> \
                                             <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;" width="33.333333333333336%">{part_name}​</td> \
                                             <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="33.333333333333336%">{part_use}​</td> \
                                          </tr>'
               dis_use_html_table_tmp1 = dis_use_html_table_tmp1 + dis_use_html_template

         dis_use_html_table_tmp2 = ''
         for part in disk_part_list[:1]:
               part_name = part["disk_mounted_on"]
               part_use = str(part["disk_use"]) + "%"
               dis_use_html_table_tmp2 = f'<tr> \
                                             <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;" width="33.333333333333336%" rowspan="{q_part_disk}">Management Disk</td> \
                                             <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;" width="33.333333333333336%">{part_name}​</td> \
                                             <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="33.333333333333336%">{part_use}​</td> \
                                             <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="33.333333333333336%" rowspan="{q_part_disk}">{disk_use_status}​</td> \
                                          </tr>'
         disk_use_html_table = dis_use_html_table_tmp2 + dis_use_html_table_tmp1


      print(f'[+] Requesting show_running_resources')
      cpu_load_avg_list = []
      cpu_load_max_list = []
      dp_prom_avg_cpu = ''
      dp_prom_max_cpu = ''
      dp_prom_cpu_status = 'ND'
      show_running_resources = request_get(host,'op&cmd','<show><running><resource-monitor><hour><last>1</last></hour></resource-monitor></running></show>',api_key)
      if show_running_resources == 'Request Error':
            print('[-] Error en la generación del request show_running_resources. Revise los parámetros e inténtelo nuevamente.')
      else:
         for dp_name, dp_values in show_running_resources['resource-monitor']['data-processors'].items():
               dp = dp_name
               for dp_key, dp_value in dp_values['hour'].items():
                  if dp_key == 'cpu-load-average':
                     for entry in dp_value['entry']:
                           for x in entry['value'].split(","):
                              cpu_load_avg_list.append(int(x))
                  if dp_key == 'cpu-load-maximum':
                     for entry in dp_value['entry']:
                           for x in entry['value'].split(","):
                              cpu_load_max_list.append(int(x))

      if len(cpu_load_avg_list) > 0:
         dp_prom_avg_cpu = round((sum(cpu_load_avg_list))/len(cpu_load_avg_list))
      if len(cpu_load_max_list) > 0:
         dp_prom_max_cpu = int((sum(cpu_load_max_list))/len(cpu_load_max_list))
      
      if dp_prom_avg_cpu < 90 and dp_prom_max_cpu < 90:
         dp_prom_cpu_status = 'OK'
      else:
         dp_prom_cpu_status = 'NOK'


      print(f'[+] Requesting show_session_info')
      dp_kbps = ''
      dp_cps = ''
      dp_pps = ''
      show_session_info = request_get(host,'op&cmd','<show><session><info/></session></show>',api_key)
      if show_session_info == 'Request Error':
         print('[-] Error en la generación del request show_session_info. Revise los parámetros e inténtelo nuevamente.')
      else:
         dp_kbps = show_session_info['kbps']
         dp_mbps = str(round((int(dp_kbps)/1024),2))
         dp_cps = show_session_info['cps']
         dp_pps = show_session_info['pps']
      

      print(f'[+] Requesting show_system_logs')
      log_list = []
      log_types = ['medium', 'high', 'critical']
      logs_query = "( severity geq 'medium' )&nlogs=1000"
      medium_logs_html_table = ''
      high_logs_html_table = ''
      critical_logs_html_table = ''
      logs_medium_list = []
      logs_high_list = []
      logs_critical_list = []
      log_types_list = [logs_medium_list, logs_high_list, logs_critical_list]
      show_system_logs = request_get(host,'log&log-type',f'system&query{logs_query}',api_key)
      if show_system_logs == 'Request Error':
         print('[-] Error en la generación del request show_session_info. Revise los parámetros e inténtelo nuevamente.')
      else:
         time.sleep(5)
         job_id = show_system_logs['job']
         get_system_logs = request_get(host,'log&action=get&job-id',job_id,api_key)
         if get_system_logs == 'Request Error':
            print('[-] Error en la generación del request show_session_info. Revise los parámetros e inténtelo nuevamente.')
         else:
               for ltype in log_types:
                  log_eventids = []
                  for log in get_system_logs['log']['logs']['entry']:
                     log_dict = {'severity':log['severity'],'subtype':log['subtype'],'eventid':log['eventid'],'description':log['opaque']}
                     log_list.append(log_dict)
                     if log_dict['severity'] == ltype:
                        if not log_dict['eventid'] in log_eventids:
                           log_eventids.append(log_dict['eventid'])
                  for logid in log_eventids:
                     i = 0
                     for log in get_system_logs['log']['logs']['entry']:
                        log_dict = {'severity':log['severity'],'subtype':log['subtype'],'eventid':log['eventid'],'description':log['opaque']}
                        if log_dict['eventid'] == logid:
                           i = i+1
                     if i == 0:
                           None
                     else:
                        if ltype == 'medium':
                           logs_medium_list.append({'severity':ltype,'eventid':logid,'count':i})
                        elif ltype == 'high':
                           logs_high_list.append({'severity':ltype,'eventid':logid,'count':i})
                        elif ltype == 'critical':
                           logs_critical_list.append({'severity':ltype,'eventid':logid,'count':i})
      log_ltype_status = 'ND'
      ltype_html_table = ''
      j = 0
      for ltype in log_types:
         ltype_html_template = ''
         ltype_html_template_1 = ''
         ltype_html_template_2 = ''
         list_logs = log_types_list[j]    
         if len(list_logs) > 0:
               log_ltype_status = 'NOK'
               for log in (list_logs)[:1]:
                  ltype_html_template_1 = f'<tr> \
                                                <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;" width="33.333333333333336%" rowspan="{len(list_logs)}">{ltype}</td> \
                                                <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;" width="33.333333333333336%">{log["eventid"]}​</td> \
                                                <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="33.333333333333336%">​{log["count"]}</td> \
                                                <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="33.333333333333336%" rowspan="{len(list_logs)}">{log_ltype_status}</td> \
                                          </tr> '
                  ltype_html_template = ltype_html_template + ltype_html_template_1
               for log in list_logs[1:]:
                  ltype_html_template_2 = f'<tr> \
                                                <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;" width="33.333333333333336%">{log["eventid"]}​</td> \
                                                <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="33.333333333333336%">{log["count"]}​</td> \
                                             </tr> '
                  ltype_html_template = ltype_html_template + ltype_html_template_2
         else:
            log_ltype_status = 'OK'
            ltype_html_template_1 = f'<tr> \
                                                <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;" width="33.333333333333336%">{ltype}</td> \
                                                <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;" width="33.333333333333336%">none</td> \
                                                <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="33.333333333333336%">​0</td> \
                                                <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="33.333333333333336%">{log_ltype_status}</td> \
                                          </tr> '
            ltype_html_template = ltype_html_template + ltype_html_template_1
         ltype_html_table = ltype_html_table + ltype_html_template
         j = j+1
            
   #     #HTML Generator
      html_style = """<style>
   * {
      box-sizing: border-box;
   }

   body {
      margin: 0;
      padding: 0;
   }

   a[x-apple-data-detectors] {
      color: inherit !important;
      text-decoration: inherit !important;
   }

   #MessageViewBody a {
      color: inherit;
      text-decoration: none;
   }

   p {
      line-height: inherit
   }

   .desktop_hide,
   .desktop_hide table {
      mso-hide: all;
      display: none;
      max-height: 0px;
      overflow: hidden;
   }

   .image_block img+div {
      display: none;
   }

   sup,
   sub {
      font-size: 75%;
      line-height: 0;
   }

   #converted-body .list_block ul,
   #converted-body .list_block ol,
   .body [class~="x_list_block"] ul,
   .body [class~="x_list_block"] ol,
   u+.body .list_block ul,
   u+.body .list_block ol {
      padding-left: 20px;
   }

   @media (max-width:768px) {
      .desktop_hide table.icons-inner {
         display: inline-block !important;
      }

      .icons-inner {
         text-align: center;
      }

      .icons-inner td {
         margin: 0 auto;
      }

      .mobile_hide {
         display: none;
      }

      .row-content {
         width: 100% !important;
      }

      .stack .column {
         width: 100%;
         display: block;
      }

      .mobile_hide {
         min-height: 0;
         max-height: 0;
         max-width: 0;
         overflow: hidden;
         font-size: 0px;
      }

      .desktop_hide,
      .desktop_hide table {
         display: table !important;
         max-height: none !important;
      }
   }
      </style> """

      html_writer = open(html_file_name,"w", encoding="utf-8")
      html_writer.write(f'<!DOCTYPE html> \
<html lang="en" xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:v="urn:schemas-microsoft-com:vml"> \
<head> \
   <title></title> \
   <meta content="text/html; charset=utf-8" http-equiv="Content-Type"/> \
   <meta content="width=device-width, initial-scale=1.0" name="viewport"/> \
   {html_style} \
</head> \
<body class="body" style="background-color: #FFFFFF; margin: 0; padding: 0; -webkit-text-size-adjust: none; text-size-adjust: none;"> \
   <table border="0" cellpadding="0" cellspacing="0" class="nl-container" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt; background-color: #FFFFFF;" width="100%"> \
      <tbody> \
         <tr> \
            <td> \
               <table align="center" border="0" cellpadding="0" cellspacing="0" class="row row-1" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt;" width="100%"> \
                  <tbody> \
                     <tr> \
                        <td> \
                           <table align="center" border="0" cellpadding="0" cellspacing="0" class="row-content stack" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt; color: #000000; width: 900px; margin: 0 auto;" width="900"> \
                              <tbody> \
                                 <tr> \
                                    <td class="column column-1" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt; font-weight: 400; text-align: left; padding-bottom: 5px; padding-top: 5px; vertical-align: top;" width="100%"> \
                                       <table border="0" cellpadding="10" cellspacing="0" class="heading_block block-1" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt;" width="100%"> \
                                          <tr> \
                                             <td class="pad"> \
                                                <h1 style="margin: 0; color: #1e0e4b; direction: ltr; font-family: Verdana, Geneva, sans-serif; font-size: 38px; font-weight: 700; letter-spacing: normal; line-height: 1.2; text-align: center; margin-top: 0; margin-bottom: 0; mso-line-height-alt: 46px;"><span class="tinyMce-placeholder" style="word-break: break-word;">Palo Alto Networks NGFW Status Report</span></h1> \
                                             </td> \
                                          </tr> \
                                       </table> \
                                       <table border="0" cellpadding="10" cellspacing="0" class="divider_block block-2" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt;" width="100%"> \
                                          <tr> \
                                             <td class="pad"> \
                                                <div align="center" class="alignment"> \
                                                   <table border="0" cellpadding="0" cellspacing="0" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt;" width="100%"> \
                                                      <tr> \
                                                         <td class="divider_inner" style="font-size: 1px; line-height: 1px; border-top: 1px solid #dddddd;"><span style="word-break: break-word;"> </span></td> \
                                                      </tr> \
                                                   </table> \
                                                </div> \
                                             </td> \
                                          </tr> \
                                       </table> \
                                       <table border="0" cellpadding="10" cellspacing="0" class="heading_block block-3" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt;" width="100%"> \
                                          <tr> \
                                             <td class="pad"> \
                                                <h2 style="margin: 0; color: #1e0e4b; direction: ltr; font-family: Verdana, Geneva, sans-serif; font-size: 30px; font-weight: 700; letter-spacing: normal; line-height: 1.2; text-align: center; margin-top: 0; margin-bottom: 0; mso-line-height-alt: 36px;"><span class="tinyMce-placeholder" style="word-break: break-word;">{system_info_list["hostname"]}  |  {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</span></h2> \
                                             </td> \
                                          </tr> \
                                       </table> \
                                    </td> \
                                 </tr> \
                              </tbody> \
                           </table> \
                        </td> \
                     </tr> \
                  </tbody> \
               </table> \
               <table align="center" border="0" cellpadding="0" cellspacing="0" class="row row-2" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt;" width="100%"> \
                  <tbody> \
                     <tr> \
                        <td> \
                           <table align="center" border="0" cellpadding="0" cellspacing="0" class="row-content stack" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt; border-radius: 0; color: #000000; width: 900px; margin: 0 auto;" width="900"> \
                              <tbody> \
                                 <tr> \
                                    <td class="column column-1" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt; font-weight: 400; text-align: left; padding-bottom: 5px; padding-top: 5px; vertical-align: top;" width="50%"> \
                                       <table border="0" cellpadding="0" cellspacing="0" class="table_block block-1" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt;" width="100%"> \
                                          <tr> \
                                             <td class="pad"> \
                                                <table style="mso-table-lspace: 0pt; mso-table-rspace: 0pt; border-collapse: collapse; width: 100%; table-layout: fixed; direction: ltr; background-color: transparent; font-family: Verdana, Geneva, sans-serif; font-weight: 400; color: #000000; text-align: left; letter-spacing: 0px;" width="100%"> \
                                                   <tbody style="vertical-align: top; font-size: 14px; line-height: 1.2; mso-line-height-alt: 17px;"> \
                                                      <tr> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;" width="50%">High Availability</td> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;" width="50%">{pan_ha_mode}</td> \
                                                      </tr> \
                                                      <tr> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;" width="50%">IP Address</td> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;" width="50%">{system_info_list["ip-address"]}</td> \
                                                      </tr> \
                                                      <tr> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;" width="50%">Model</td> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;" width="50%">{system_info_list["model"]}</td> \
                                                      </tr> \
                                                         </tr> \
                                                         <tr> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;" width="50%">Multi Vsys</td> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;" width="50%">{system_info_list["multi-vsys"]}</td> \
                                                      </tr> \
                                                         <tr> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;" width="50%">Serial Number</td> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;" width="50%">{system_info_list["serial"]}</td> \
                                                      </tr> \
                                                      <tr> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;" width="50%">Uptime</td> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;" width="50%">{system_info_list["uptime"]}</td> \
                                                   </tbody> \
                                                </table> \
                                             </td> \
                                          </tr> \
                                       </table> \
                                    </td> \
                                    <td class="column column-2" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt; font-weight: 400; text-align: left; padding-bottom: 5px; padding-top: 5px; vertical-align: top;" width="50%"> \
                                       <table border="0" cellpadding="40" cellspacing="0" class="image_block block-1" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt;" width="100%"> \
                                          <tr> \
                                             <td class="pad"> \
                                                <div align="center" class="alignment"> \
                                                   <div style="max-width: 370px;" ><img alt="" height="auto" src="{pan_image}" style="display: block; height: auto; border: 0; width: 100%;" title="" width="370"/></div> \
                                                </div> \
                                             </td> \
                                          </tr> \
                                       </table> \
                                    </td> \
                                 </tr> \
                              </tbody> \
                           </table> \
                        </td> \
                     </tr> \
                  </tbody> \
               </table> \
               <table align="center" border="0" cellpadding="0" cellspacing="0" class="row row-3" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt;" width="100%"> \
                  <tbody> \
                     <tr> \
                        <td> \
                           <table align="center" border="0" cellpadding="0" cellspacing="0" class="row-content stack" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt; border-radius: 0; color: #000000; width: 900px; margin: 0 auto;" width="900"> \
                              <tbody> \
                                 <tr> \
                                    <td class="column column-1" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt; font-weight: 400; text-align: left; padding-bottom: 5px; padding-top: 5px; vertical-align: top;" width="100%"> \
                                       <table border="0" cellpadding="10" cellspacing="0" class="divider_block block-1" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt;" width="100%"> \
                                          <tr> \
                                             <td class="pad"> \
                                                <div align="center" class="alignment"> \
                                                   <table border="0" cellpadding="0" cellspacing="0" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt;" width="100%"> \
                                                      <tr> \
                                                         <td class="divider_inner" style="font-size: 1px; line-height: 1px; border-top: 1px solid #dddddd;"><span style="word-break: break-word;"> </span></td> \
                                                      </tr> \
                                                   </table> \
                                                </div> \
                                             </td> \
                                          </tr> \
                                       </table> \
                                    </td> \
                                 </tr> \
                              </tbody> \
                           </table> \
                        </td> \
                     </tr> \
                  </tbody> \
               </table> \
               <table align="center" border="0" cellpadding="0" cellspacing="0" class="row row-4" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt;" width="100%"> \
                  <tbody> \
                     <tr> \
                        <td> \
                           <table align="center" border="0" cellpadding="0" cellspacing="0" class="row-content stack" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt; border-radius: 0; color: #000000; width: 900px; margin: 0 auto;" width="900"> \
                              <tbody> \
                                 <tr> \
                                    <td class="column column-1" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt; font-weight: 400; text-align: left; padding-bottom: 5px; padding-top: 5px; vertical-align: top;" width="100%"> \
                                       <table border="0" cellpadding="10" cellspacing="0" class="heading_block block-1" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt;" width="100%"> \
                                          <tr> \
                                             <td class="pad"> \
                                                <h3 style="margin: 0; color: #1e0e4b; direction: ltr; font-family: Verdana, Geneva, sans-serif; font-size: 24px; font-weight: 700; letter-spacing: normal; line-height: 1.2; text-align: left; margin-top: 0; margin-bottom: 0; mso-line-height-alt: 29px;"><span class="tinyMce-placeholder" style="word-break: break-word;">1. System</span></h3> \
                                             </td> \
                                          </tr> \
                                       </table> \
                                       <table border="0" cellpadding="10" cellspacing="0" class="table_block block-2" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt;" width="100%"> \
                                          <tr> \
                                             <td class="pad"> \
                                                <table style="mso-table-lspace: 0pt; mso-table-rspace: 0pt; border-collapse: collapse; width: 100%; table-layout: fixed; direction: ltr; background-color: transparent; font-family: Verdana, Geneva, sans-serif; font-weight: 400; color: #101112; text-align: left; letter-spacing: 0px;" width="100%"> \
                                                   <thead style="vertical-align: top; background-color: #f2f2f2; color: #101112; font-size: 14px; line-height: 1.2; mso-line-height-alt: 17px;"> \
                                                      <tr> \
                                                         <th style="padding: 10px; word-break: break-word; font-weight: 700; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd; text-align: center;" width="33.333333333333336%">ITEM</th> \
                                                         <th style="padding: 10px; word-break: break-word; font-weight: 700; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd; text-align: center;" width="33.333333333333336%">VALUE</th> \
                                                         <th style="padding: 10px; word-break: break-word; font-weight: 700; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd; text-align: center;" width="33.333333333333336%">STATUS</th> \
                                                      </tr> \
                                                   </thead> \
                                                   <tbody style="vertical-align: top; font-size: 16px; line-height: 1.2; mso-line-height-alt: 19px;"> \
                                                      <tr> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;" width="33.333333333333336%">Config File Size</td> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="33.333333333333336%">{pan_config_file_size} KB</td> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="33.333333333333336%">{pan_config_status_code}</td> \
                                                      </tr> \
                                                      <tr> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;" width="33.333333333333336%">Date and Time</td> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="33.333333333333336%">{pan_time}</td> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="33.333333333333336%">{pan_time_status}</td> \
                                                      </tr> \
                                                      <tr> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;" width="33.333333333333336%">Device Certificate Status</td> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="33.333333333333336%">{pan_device_cert}</td> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="33.333333333333336%">{pan_device_cert_status}</td> \
                                                      </tr> \
                                                      <tr> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;" width="33.333333333333336%">Software Status</td> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="33.333333333333336%">{system_software_running}</td> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="33.333333333333336%">{system_software_status}</td> \
                                                      </tr> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;" width="33.333333333333336%">Software Version</td> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="33.333333333333336%">{system_info_list["sw-version"]}</td> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="33.333333333333336%">{panos_version_status}</td> \
                                                      </tr> \
                                                   </tbody> \
                                                </table> \
                                             </td> \
                                          </tr> \
                                       </table> \
                                       <table border="0" cellpadding="10" cellspacing="0" class="heading_block block-3" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt;" width="100%"> \
                                          <tr> \
                                             <td class="pad"> \
                                                <h3 style="margin: 0; color: #1e0e4b; direction: ltr; font-family: Verdana, Geneva, sans-serif; font-size: 24px; font-weight: 700; letter-spacing: normal; line-height: 1.2; text-align: left; margin-top: 0; margin-bottom: 0; mso-line-height-alt: 29px;"><span class="tinyMce-placeholder" style="word-break: break-word;">2. Dynamic Updates</span></h3> \
                                             </td> \
                                          </tr> \
                                       </table> \
                                       <table border="0" cellpadding="10" cellspacing="0" class="table_block block-4" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt;" width="100%"> \
                                          <tr> \
                                             <td class="pad"> \
                                                <table style="mso-table-lspace: 0pt; mso-table-rspace: 0pt; border-collapse: collapse; width: 100%; table-layout: fixed; direction: ltr; background-color: transparent; font-family: Verdana, Geneva, sans-serif; font-weight: 400; color: #101112; text-align: left; letter-spacing: 0px;" width="100%"> \
                                                   <thead style="vertical-align: center; background-color: #f2f2f2; color: #101112; font-size: 14px; line-height: 1.2; mso-line-height-alt: 17px;"> \
                                                      <tr> \
                                                         <th style="padding: 10px; word-break: break-word; font-weight: 700; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd; text-align: center;" width="33.333333333333336%">ITEM</th> \
                                                         <th style="padding: 10px; word-break: break-word; font-weight: 700; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd; text-align: center;" width="33.333333333333336%">VALUE</th> \
                                                         <th style="padding: 10px; word-break: break-word; font-weight: 700; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd; text-align: center;" width="33.333333333333336%">STATUS</th> \
                                                      </tr> \
                                                   </thead> \
                                                   <tbody style="vertical-align: center; font-size: 16px; line-height: 1.2; mso-line-height-alt: 19px;"> \
                                                      {sign_release_html_table} \
                                                   </tbody> \
                                                </table> \
                                             </td> \
                                          </tr> \
                                       </table> \
                                       <table border="0" cellpadding="10" cellspacing="0" class="heading_block block-5" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt;" width="100%"> \
                                          <tr> \
                                             <td class="pad"> \
                                                <h3 style="margin: 0; color: #1e0e4b; direction: ltr; font-family: Verdana, Geneva, sans-serif; font-size: 24px; font-weight: 700; letter-spacing: normal; line-height: 1.2; text-align: left; margin-top: 0; margin-bottom: 0; mso-line-height-alt: 29px;">3. Enviromentals</h3> \
                                             </td> \
                                          </tr> \
                                       </table> \
                                       <table border="0" cellpadding="10" cellspacing="0" class="table_block block-6" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt;" width="100%"> \
                                          <tr> \
                                             <td class="pad"> \
                                                <table style="mso-table-lspace: 0pt; mso-table-rspace: 0pt; border-collapse: collapse; width: 100%; table-layout: fixed; direction: ltr; background-color: transparent; font-family: Verdana, Geneva, sans-serif; font-weight: 400; color: #101112; text-align: left; letter-spacing: 0px;" width="100%"> \
                                                   <thead style="vertical-align: center; background-color: #f2f2f2; color: #101112; font-size: 14px; line-height: 1.2; mso-line-height-alt: 17px;"> \
                                                      <tr> \
                                                         <th style="padding: 10px; word-break: break-word; font-weight: 700; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd; text-align: center;" width="33.333333333333336%">ITEM</th> \
                                                         <th style="padding: 10px; word-break: break-word; font-weight: 700; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd; text-align: center;" width="33.333333333333336%">VALUE</th> \
                                                         <th style="padding: 10px; word-break: break-word; font-weight: 700; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd; text-align: center;" width="33.333333333333336%">STATUS</th> \
                                                      </tr> \
                                                   </thead> \
                                                   <tbody style="vertical-align: center; font-size: 16px; line-height: 1.2; mso-line-height-alt: 19px;"> \
                                                      <tr> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;" width="33.333333333333336%">Alarms</td> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="33.333333333333336%">{enviromental_item_alarm}​</td> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="33.333333333333336%">{enviromental_status}​</td> \
                                                      </tr> \
                                                   </tbody> \
                                                </table> \
                                             </td> \
                                          </tr> \
                                       </table> \
                                       <table border="0" cellpadding="10" cellspacing="0" class="heading_block block-7" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt;" width="100%"> \
                                          <tr> \
                                             <td class="pad"> \
                                                <h3 style="margin: 0; color: #1e0e4b; direction: ltr; font-family: Verdana, Geneva, sans-serif; font-size: 24px; font-weight: 700; letter-spacing: normal; line-height: 1.2; text-align: left; margin-top: 0; margin-bottom: 0; mso-line-height-alt: 29px;"><span class="tinyMce-placeholder" style="word-break: break-word;">4. High Availability</span></h3> \
                                             </td> \
                                          </tr> \
                                       </table> \
                                       <table border="0" cellpadding="10" cellspacing="0" class="table_block block-8" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt;" width="100%"> \
                                          <tr> \
                                             <td class="pad"> \
                                                <table style="mso-table-lspace: 0pt; mso-table-rspace: 0pt; border-collapse: collapse; width: 100%; table-layout: fixed; direction: ltr; background-color: transparent; font-family: Verdana, Geneva, sans-serif; font-weight: 400; color: #101112; text-align: left; letter-spacing: 0px;" width="100%"> \
                                                   <thead style="vertical-align: center; background-color: #f2f2f2; color: #101112; font-size: 14px; line-height: 1.2; mso-line-height-alt: 17px;"> \
                                                      <tr> \
                                                         <th style="padding: 10px; word-break: break-word; font-weight: 700; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd; text-align: center;" width="30%">ITEM</th> \
                                                         <th style="padding: 10px; word-break: break-word; font-weight: 700; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd; text-align: center;" width="40%" colspan="2">VALUE</th> \
                                                         <th style="padding: 10px; word-break: break-word; font-weight: 700; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd; text-align: center;" width="30%">STATUS</th> \
                                                      </tr> \
                                                   </thead> \
                                                   <tbody style="vertical-align: center; font-size: 16px; line-height: 1.2; mso-line-height-alt: 19px;"> \
                                                      <tr> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;" width="33.333333333333336%" rowspan="4">HA Compatibility</td> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;" width="33.333333333333336%">PanOS Version</td> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="33.333333333333336%">{pan_ha_build_compat}​</td> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="33.333333333333336%" rowspan="4">{pan_ha_compat}​</td> \
                                                      </tr> \
                                                      <tr> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;" width="33.333333333333336%">Applications​</td> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="33.333333333333336%">{pan_ha_app_compat}​</td> \
                                                      </tr> \
                                                      <tr> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;" width="33.333333333333336%">Threats</td> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="33.333333333333336%">{pan_ha_threat_compat}​</td> \
                                                      </tr> \
                                                      <tr> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;" width="33.333333333333336%">Antivirus</td> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="33.333333333333336%">{pan_ha_av_compat}​</td> \
                                                      </tr> \
                                                      <tr> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;" width="30%">Config Sync</td> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="40%" colspan="2">{pan_ha_running_sync}​</td> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="30%">{pan_ha_sync_status}​</td> \
                                                      </tr> \
                                                   </tbody> \
                                                </table> \
                                             </td> \
                                          </tr> \
                                       </table> \
                                       <table border="0" cellpadding="10" cellspacing="0" class="heading_block block-9" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt;" width="100%"> \
                                          <tr> \
                                             <td class="pad"> \
                                                <h3 style="margin: 0; color: #1e0e4b; direction: ltr; font-family: Verdana, Geneva, sans-serif; font-size: 24px; font-weight: 700; letter-spacing: normal; line-height: 1.2; text-align: left; margin-top: 0; margin-bottom: 0; mso-line-height-alt: 29px;"><span class="tinyMce-placeholder" style="word-break: break-word;">5. Interfaces</span></h3> \
                                             </td> \
                                          </tr> \
                                       </table> \
                                       <table border="0" cellpadding="10" cellspacing="0" class="list_block block-10" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt; word-break: break-word; color: #101112; direction: ltr; font-family: Verdana, Geneva, sans-serif; font-size: 16px; font-weight: 400; letter-spacing: 0px; line-height: 1.2; text-align: left; mso-line-height-alt: 19px;" width="100%"> \
                                          <tr> \
                                             <td class="pad"> \
                                                <div style="margin-left:-20px"> \
                                                   <ul start="1" style="margin-top: 0; margin-bottom: 0; list-style-type: revert;"> \
                                                      <li style="Margin: 0 0 0 0;">Management</li> \
                                                   </ul> \
                                                </div> \
                                             </td> \
                                          </tr> \
                                       </table> \
                                       <table border="0" cellpadding="10" cellspacing="0" class="table_block block-11" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt;" width="100%"> \
                                          <tr> \
                                             <td class="pad"> \
                                                <table style="mso-table-lspace: 0pt; mso-table-rspace: 0pt; border-collapse: collapse; width: 100%; table-layout: fixed; direction: ltr; background-color: transparent; font-family: Verdana, Geneva, sans-serif; font-weight: 400; color: #101112; text-align: left; letter-spacing: 0px;" width="100%"> \
                                                   <thead style="vertical-align: center; background-color: #f2f2f2; color: #101112; font-size: 14px; line-height: 1.2; mso-line-height-alt: 17px;"> \
                                                      <tr> \
                                                         <th style="padding: 10px; word-break: break-word; font-weight: 700; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd; text-align: center;" width="30%">ITEM</th> \
                                                         <th style="padding: 10px; word-break: break-word; font-weight: 700; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd; text-align: center;" width="40%" colspan="2">VALUE</th> \
                                                         <th style="padding: 10px; word-break: break-word; font-weight: 700; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd; text-align: center;" width="30%">STATUS</th> \
                                                      </tr> \
                                                   </thead> \
                                                   <tbody style="vertical-align: center; font-size: 16px; line-height: 1.2; mso-line-height-alt: 19px;"> \
                                                      <tr> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;" width="33.333333333333336%"rowspan="2">management</td> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;" width="50%">Runtime Status​</td> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="50%">{mgmt_if_runtime_info}​</td> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="33.333333333333336"rowspan="2">{mgmt_if_hw_status}​</td> \
                                                      </tr> \
                                                      <tr> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;" width="50%">Error Counters​</td> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="50%">{len(mgmt_if_err_drops)}​</td> \
                                                      </tr> \
                                                   </tbody> \
                                                </table> \
                                             </td> \
                                          </tr> \
                                       </table> \
                                       <table border="0" cellpadding="10" cellspacing="0" class="list_block block-12" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt; word-break: break-word; color: #101112; direction: ltr; font-family: Verdana, Geneva, sans-serif; font-size: 16px; font-weight: 400; letter-spacing: 0px; line-height: 1.2; text-align: left; mso-line-height-alt: 19px;" width="100%"> \
                                          <tr> \
                                             <td class="pad"> \
                                                <div style="margin-left:-20px"> \
                                                   <ul style="margin-top: 0; margin-bottom: 0; list-style-type: revert;"> \
                                                      <li style="Margin: 0 0 0 0;">Dataplane</li> \
                                                   </ul> \
                                                </div> \
                                             </td> \
                                          </tr> \
                                       </table> \
                                       <table border="0" cellpadding="10" cellspacing="0" class="table_block block-13" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt;" width="100%"> \
                                          <tr> \
                                             <td class="pad"> \
                                                <table style="mso-table-lspace: 0pt; mso-table-rspace: 0pt; border-collapse: collapse; width: 100%; table-layout: fixed; direction: ltr; background-color: transparent; font-family: Verdana, Geneva, sans-serif; font-weight: 400; color: #101112; text-align: left; letter-spacing: 0px;" width="100%"> \
                                                   <thead style="vertical-align: center; background-color: #f2f2f2; color: #101112; font-size: 14px; line-height: 1.2; mso-line-height-alt: 17px;"> \
                                                      <tr> \
                                                         <th style="padding: 10px; word-break: break-word; font-weight: 700; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd; text-align: center;" width="30%">ITEM</th> \
                                                         <th style="padding: 10px; word-break: break-word; font-weight: 700; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd; text-align: center;" width="40%" colspan="2">VALUE</th> \
                                                         <th style="padding: 10px; word-break: break-word; font-weight: 700; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd; text-align: center;" width="30%">STATUS</th> \
                                                      </tr> \
                                                   </thead> \
                                                   <tbody style=vertical-align: center; font-size: 16px; line-height: 1.2; mso-line-height-alt: 19px;"> \
                                                      {hw_ifs_html_table} \
                                                   </tbody> \
                                                </table> \
                                             </td> \
                                          </tr> \
                                       </table> \
                                       <table border="0" cellpadding="10" cellspacing="0" class="list_block block-14" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt; word-break: break-word; color: #101112; direction: ltr; font-family: Verdana, Geneva, sans-serif; font-size: 16px; font-weight: 400; letter-spacing: 0px; line-height: 1.2; text-align: left; mso-line-height-alt: 19px;" width="100%"> \
                                          <tr> \
                                             <td class="pad"> \
                                                <div style="margin-left:-20px"> \
                                                <ul style="margin-top: 0; margin-bottom: 0; list-style-type: revert;"> \
                                       </table> \
                                       <table border="0" cellpadding="10" cellspacing="0" class="heading_block block-16" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt;" width="100%"> \
                                          <tr> \
                                             <td class="pad"> \
                                                <h3 style="margin: 0; color: #1e0e4b; direction: ltr; font-family: Verdana, Geneva, sans-serif; font-size: 24px; font-weight: 700; letter-spacing: normal; line-height: 1.2; text-align: left; margin-top: 0; margin-bottom: 0; mso-line-height-alt: 29px;"><span class="tinyMce-placeholder" style="word-break: break-word;">6. Licensing</span></h3> \
                                             </td> \
                                          </tr> \
                                       </table> \
                                       <table border="0" cellpadding="10" cellspacing="0" class="table_block block-17" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt;" width="100%"> \
                                          <tr> \
                                             <td class="pad"> \
                                                <table style="mso-table-lspace: 0pt; mso-table-rspace: 0pt; border-collapse: collapse; width: 100%; table-layout: fixed; direction: ltr; background-color: transparent; font-family: Verdana, Geneva, sans-serif; font-weight: 400; color: #101112; text-align: left; letter-spacing: 0px;" width="100%"> \
                                                   <thead style="vertical-align: top; background-color: #f2f2f2; color: #101112; font-size: 14px; line-height: 1.2; mso-line-height-alt: 17px;"> \
                                                      <tr> \
                                                         <th style="padding: 10px; word-break: break-word; font-weight: 700; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd; text-align: center;" width="33.333333333333336%">FEATURE</th> \
                                                         <th style="padding: 10px; word-break: break-word; font-weight: 700; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd; text-align: center;" width="33.333333333333336%">VALIDITY</th> \
                                                         <th style="padding: 10px; word-break: break-word; font-weight: 700; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd; text-align: center;" width="33.333333333333336%">STATUS</th> \
                                                      </tr> \
                                                   </thead> \
                                                   <tbody style="vertical-align: top; font-size: 16px; line-height: 1.2; mso-line-height-alt: 19px;"> \
                                                      {licenses_html_table} \
                                                   </tbody> \
                                                </table> \
                                             </td> \
                                          </tr> \
                                       </table> \
                                       <table border="0" cellpadding="10" cellspacing="0" class="heading_block block-18" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt;" width="100%"> \
                                          <tr> \
                                             <td class="pad"> \
                                                <h3 style="margin: 0; color: #1e0e4b; direction: ltr; font-family: Verdana, Geneva, sans-serif; font-size: 24px; font-weight: 700; letter-spacing: normal; line-height: 1.2; text-align: left; margin-top: 0; margin-bottom: 0; mso-line-height-alt: 29px;"><span class="tinyMce-placeholder" style="word-break: break-word;">7. Management</span></h3> \
                                             </td> \
                                          </tr> \
                                       </table> \
                                       <table border="0" cellpadding="10" cellspacing="0" class="table_block block-19" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt;" width="100%"> \
                                          <tr> \
                                             <td class="pad"> \
                                                <table style="mso-table-lspace: 0pt; mso-table-rspace: 0pt; border-collapse: collapse; width: 100%; table-layout: fixed; direction: ltr; background-color: transparent; font-family: Verdana, Geneva, sans-serif; font-weight: 400; color: #101112; text-align: left; letter-spacing: 0px;" width="100%"> \
                                                   <thead style="vertical-align: top; background-color: #f2f2f2; color: #101112; font-size: 14px; line-height: 1.2; mso-line-height-alt: 17px;"> \
                                                      <tr> \
                                                         <th style="padding: 10px; word-break: break-word; font-weight: 700; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd; text-align: center;" width="33.333333333333336%">SERVER</th> \
                                                         <th style="padding: 10px; word-break: break-word; font-weight: 700; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd; text-align: center;" width="33.333333333333336%">CONNECTED</th> \
                                                         <th style="padding: 10px; word-break: break-word; font-weight: 700; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd; text-align: center;" width="33.333333333333336%">STATUS</th> \
                                                      </tr> \
                                                   </thead> \
                                                   <tbody style="vertical-align: top; font-size: 16px; line-height: 1.2; mso-line-height-alt: 19px;"> \
                                                      {panorama_html_table} \
                                                   </tbody> \
                                                </table> \
                                             </td> \
                                          </tr> \
                                       </table> \
                                       <table border="0" cellpadding="10" cellspacing="0" class="heading_block block-20" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt;" width="100%"> \
                                          <tr> \
                                             <td class="pad"> \
                                                <h3 style="margin: 0; color: #1e0e4b; direction: ltr; font-family: Verdana, Geneva, sans-serif; font-size: 24px; font-weight: 700; letter-spacing: normal; line-height: 1.2; text-align: left; margin-top: 0; margin-bottom: 0; mso-line-height-alt: 29px;"><span class="tinyMce-placeholder" style="word-break: break-word;">8. Monitor</span></h3> \
                                             </td> \
                                          </tr> \
                                       </table> \
                                       <table border="0" cellpadding="10" cellspacing="0" class="table_block block-21" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt;" width="100%"> \
                                          <tr> \
                                             <td class="pad"> \
                                                <table style="mso-table-lspace: 0pt; mso-table-rspace: 0pt; border-collapse: collapse; width: 100%; table-layout: fixed; direction: ltr; background-color: transparent; font-family: Verdana, Geneva, sans-serif; font-weight: 400; color: #101112; text-align: left; letter-spacing: 0px;" width="100%"> \
                                                   <thead style="vertical-align: top; background-color: #f2f2f2; color: #101112; font-size: 14px; line-height: 1.2; mso-line-height-alt: 17px;"> \
                                                      <tr> \
                                                         <th style="padding: 10px; word-break: break-word; font-weight: 700; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd; text-align: center;" width="20%">SEVERITY</th> \
                                                         <th style="padding: 10px; word-break: break-word; font-weight: 700; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd; text-align: center;" width="60%" colspan="2">VALUES</th> \
                                                         <th style="padding: 10px; word-break: break-word; font-weight: 700; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd; text-align: center;" width="20%">STATUS</th> \
                                                      </tr> \
                                                   </thead> \
                                                   <tbody style="vertical-align: center; font-size: 16px; line-height: 1.2; mso-line-height-alt: 19px;"> \
                                                   {ltype_html_table} \
                                                   </tbody> \
                                                </table> \
                                             </td> \
                                          </tr> \
                                       </table> \
                                       <table border="0" cellpadding="10" cellspacing="0" class="heading_block block-22" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt;" width="100%"> \
                                          <tr> \
                                             <td class="pad"> \
                                                <h3 style="margin: 0; color: #1e0e4b; direction: ltr; font-family: Verdana, Geneva, sans-serif; font-size: 24px; font-weight: 700; letter-spacing: normal; line-height: 1.2; text-align: left; margin-top: 0; margin-bottom: 0; mso-line-height-alt: 29px;"><span class="tinyMce-placeholder" style="word-break: break-word;">9. Usage (Instant)</span></h3> \
                                             </td> \
                                          </tr> \
                                       </table> \
                                       <table border="0" cellpadding="10" cellspacing="0" class="table_block block-23" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt;" width="100%"> \
                                          <tr> \
                                             <td class="pad"> \
                                                <table style="mso-table-lspace: 0pt; mso-table-rspace: 0pt; border-collapse: collapse; width: 100%; table-layout: fixed; direction: ltr; background-color: transparent; font-family: Verdana, Geneva, sans-serif; font-weight: 400; color: #101112; text-align: left; letter-spacing: 0px;" width="100%"> \
                                                   <thead style="vertical-align: center; background-color: #f2f2f2; color: #101112; font-size: 14px; line-height: 1.2; mso-line-height-alt: 17px;"> \
                                                      <tr> \
                                                         <th style="padding: 10px; word-break: break-word; font-weight: 700; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd; text-align: center;" width="33.333333333333336%">ITEM</th> \
                                                         <th style="padding: 10px; word-break: break-word; font-weight: 700; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd; text-align: center;" width="33.333333333333336%" colspan="2">VALUE</th> \
                                                         <th style="padding: 10px; word-break: break-word; font-weight: 700; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd; text-align: center;" width="33.333333333333336%">STATUS</th> \
                                                      </tr> \
                                                   </thead> \
                                                   <tbody style="vertical-align: center; font-size: 16px; line-height: 1.2; mso-line-height-alt: 19px;"> \
                                                      <tr> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;" width="33.333333333333336%">Management CPU</td> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="33.333333333333336%" colspan="2">{mp_cpu_us_str}​</td> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="33.333333333333336%">{mp_cpu_us_status}</td> \
                                                      </tr> \
                                                      {disk_use_html_table} \
                                                      <tr> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;" width="33.333333333333336%">Management Memory</td> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="33.333333333333336%" colspan="2">{mp_mem_us_str}​</td> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="33.333333333333336%">{mp_mem_us_status}​</td> \
                                                      </tr> \
                                                      <tr> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;" width="33.333333333333336%" rowspan="2">Dataplane CPU</td> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;" width="33.333333333333336%">Average Usage​</td> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="33.333333333333336%">{dp_prom_avg_cpu}%</td> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="33.333333333333336%" rowspan="2">{dp_prom_cpu_status}​</td> \
                                                      </tr> \
                                                      <tr> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;" width="33.333333333333336%">Maximum Usage</td> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="33.333333333333336%">{dp_prom_max_cpu}%​</td> \
                                                      </tr> \
                                                      <tr> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;" width="33.333333333333336%">Dataplane Throughput (Mbps)</td> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="33.333333333333336%" colspan="2">{dp_mbps}</td> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="33.333333333333336%">NA​</td> \
                                                      </tr> \
                                                      <tr> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;" width="33.333333333333336%">Dataplane Sessions (Cps)</td> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="33.333333333333336%" colspan="2">{dp_cps}​</td> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="33.333333333333336%">NA​</td> \
                                                      </tr> \
                                                      <tr> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;" width="33.333333333333336%">Dataplane Packets (Pps)</td> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="33.333333333333336%" colspan="2">{dp_pps}​</td> \
                                                         <td style="padding: 10px; word-break: break-word; border-top: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; border-left: 1px solid #dddddd;text-align: center;" width="33.333333333333336%">NA​</td> \
                                                      </tr> \
                                                   </tbody> \
                                                </table> \
                                             </td> \
                                          </tr> \
                                       </table> \
                                    </td> \
                                 </tr> \
                              </tbody> \
                           </table> \
                        </td> \
                     </tr> \
                  </tbody> \
               </table> \
               <table align="center" border="0" cellpadding="0" cellspacing="0" class="row row-5" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt; background-color: #ffffff;" width="100%"> \
                  <tbody> \
                     <tr> \
                        <td> \
                           <table align="center" border="0" cellpadding="0" cellspacing="0" class="row-content stack" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt; color: #000000; background-color: #ffffff; width: 900px; margin: 0 auto;" width="900"> \
                              <tbody> \
                                 <tr> </tr> \
                           </table> \
                        </td> \
                     </tr> \
               </table> \
            </td> \
         </tr> \
      </tbody> \
   </table> \
   </td> \
   </tr> \
   </tbody> \
   </table> \
   </td> \
   </tr> \
   </tbody> \
   </table><!-- End --> \
</body> \
</html>')  
      html_writer.close()
      print(f'[+] Archivo {html_file_name} generado exitosamente.')

if __name__ == '__main__':
    main()