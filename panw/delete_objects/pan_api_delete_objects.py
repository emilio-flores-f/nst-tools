import xmltodict, requests, sys, time, getpass
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

api_host = sys.argv[1]
api_key = getpass.getpass("Ingrese la API Key: ")

def api_request(request_type,host,command,key):    
    request = xmltodict.parse(request_type(f"https://{host}/api/?type={command}&key={key}", verify=False).content)
    return request

def main():
    delete_object_list = []
    devices = []
    show_devices =  api_request(requests.get,api_host,f"config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/device-group/entry",api_key)
    for device in show_devices['response']['result']['entry']:
        #Excluye Prisma Access DG's
        if not device['@name'] == 'Service_Conn_Device_Group' and not device['@name'] == 'Mobile_User_Device_Group':
            devices.append(device['@name'])
    object_types = ['address-group','address','service-group','service','tag']
    start_time = time.time()
    for device in devices:
        print(f"\n{'#'*50} {device} {'#'*50}")
        for object_type in object_types:
            if device == 'shared':
                show_object = api_request(requests.get,api_host,f"config&action=get&xpath=/config/{device}/{object_type}",api_key)
            else:
                show_object = api_request(requests.get,api_host,f"config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='{device}']/{object_type}",api_key)
            i = 0
            if not show_object['response']['result'] == None and not show_object['response']['result'][object_type] == None:
                #validar output
                if isinstance(show_object['response']['result'][object_type]['entry'],list):
                    for object_n in show_object['response']['result'][object_type]['entry']:
                        object_n_name = object_n['@name']
                        if device == 'shared':
                            request_delete = api_request(requests.post,api_host,f"config&action=delete&xpath=/config/{device}/{object_type}/entry[@name='{object_n_name}']",api_key)
                            if request_delete['response']['@status'] == 'success' and request_delete['response']['@code'] == '20':
                                i = i+1
                                delete_object_list.append(f'delete shared {object_n["@name"]}\n')
                                print(f'Objeto shared {object_type} {object_n["@name"]} marcado para eliminación')
                        else:
                            request_delete = api_request(requests.post,api_host,f"config&action=delete&xpath=/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='{device}']/{object_type}/entry[@name='{object_n_name}']",api_key)
                            if request_delete['response']['@status'] == 'success' and request_delete['response']['@code'] == '20':
                                i = i+1
                                delete_object_list.append(f'delete device-group {device} {object_type} {object_n["@name"]}\n')
                                print(f'Objeto {device} {object_type} {object_n["@name"]} marcado para eliminación')
    if len(delete_object_list) > 0:
        print(f'[+] Total de objetos marcados para eliminación: {len(delete_object_list)}')
        filename = "output_file_"+time.strftime("%Y%m%d-%H%M%S")+".txt"
        with open(filename, 'w') as f:
            for x in delete_object_list:
                f.write(x)
        print(f'[+] Se ha escrito el total de registros en el archivo output_file.txt')
    else:
        print('[-] No se detectaron objetos sin uso')
    print(f'[+] Tiempo de ejecución: {round(time.time()-start_time)} segundos')

if __name__ == '__main__':
    main()