import xmltodict, argparse, requests
from prettytable import PrettyTable
from getpass import getpass
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

parser = argparse.ArgumentParser()
parser.add_argument("-t", help="Analysis type, file or api", type=str, required=True)
args = parser.parse_args()

security_rules = []
no_log_end = []
no_log_setting = []
no_security_profile = []
allow_any_source_or_destination = []
allow_any_source_and_destination = []
any_application = []
any_application_and_service = []
any_zone = []
disabled = []
rule_score = []

def request_api_key(host,username,password):
    request = xmltodict.parse(requests.get(f'https://{host}/api/?type=keygen&user={username}&password={password}', verify=False).content)
    if request['response']['@status'] == 'success':
        return(request['response']['result']['key'])
    else:
        return('API Key Error')

def request_op_get(host,command,key):    
    request = xmltodict.parse(requests.get(f'https://{host}/api/?type=op&cmd={command}&key={key}', verify=False).content)
    if request['response']['@status'] == 'success':
        return(request['response']['result'])
    else:
        return('Request Error')

def ruleAnalysis(hostname,item_name,item_value,rule,default_flag):
    score = 0
    # Log End
    if 'log-end' in rule.keys():
        if rule['log-end'] == 'yes':    
            None
        else:
            linea_dict = {'device':hostname,item_name:item_value,'rule':rule['@name'],'issue':'no log-end'}
            no_log_end.append(linea_dict)
            score = score+1
    else:
        linea_dict = {'device':hostname,item_name:item_value,'rule':rule['@name'],'issue':'no log-end'}
        no_log_end.append(linea_dict)
        score = score+1
    # Log Forwarding
    if 'log-setting' in rule.keys():
        if len(rule['log-setting']) > 0:
            None
        else:
            linea_dict = {'device':hostname,item_name:item_value,'rule':rule['@name'],'issue':'no log-setting'}
            no_log_setting.append(linea_dict)
            score = score+1
    else:
        linea_dict = {'device':hostname,item_name:item_value,'rule':rule['@name'],'issue':'no log-setting'}
        no_log_setting.append(linea_dict)
        score = score+1
    # Security Profile
    if 'profile-setting' in rule.keys():
        if 'group' in rule['profile-setting'].keys():
            if rule['profile-setting']['group'] == 'None' and rule['action'] == 'allow':
                linea_dict = {'device':hostname,item_name:item_value,'rule':rule['@name'],'issue':'no profile-setting'}
                no_security_profile.append(linea_dict)
                score = score+1
            else: None
        elif 'profiles' in rule['profile-setting'].keys():
            if rule['profile-setting']['profiles'] == 'None' and rule['action'] == 'allow':
                linea_dict = {'device':hostname,item_name:item_value,'rule':rule['@name'],'issue':'no profile-setting'}
                no_security_profile.append(linea_dict)
                score = score+1
            else: None
        else:
            if rule['action'] == 'allow':
                linea_dict = {'device':hostname,item_name:item_value,'rule':rule['@name'],'issue':'no profile-setting'}
                no_security_profile.append(linea_dict)
                score = score+1
            else: None
    else:
        if rule['action'] == 'allow':
            linea_dict = {'device':hostname,item_name:item_value,'rule':rule['@name'],'issue':'no profile-setting'}
            no_security_profile.append(linea_dict)
            score = score+1
        else: 
            None
    # any Source or any Destination and Action allow without user
    if default_flag == 'yes':
        None
    else:
        if 'source-user' in rule.keys():
            if (rule['source']['member'] == 'any' or rule['destination']['member'] == 'any') and rule['action'] == 'allow' and rule['source-user']['member'] == 'any':
                linea_dict = {'device':hostname,item_name:item_value,'rule':rule['@name'],'issue':'allow traffic from any source or destination without user'}
                allow_any_source_or_destination.append(linea_dict)
                score = score+1
            else: None
        else:
            if (rule['source']['member'] == 'any' or rule['destination']['member'] == 'any') and rule['action'] == 'allow':
                linea_dict = {'device':hostname,item_name:item_value,'rule':rule['@name'],'issue':'allow traffic from any source or destination without user'}
                allow_any_source_or_destination.append(linea_dict)
                score = score+1
        # any Source and any Destination and Action allow without user
        if 'source-user' in rule.keys():
            if (rule['source']['member'] == 'any' and rule['destination']['member'] == 'any') and rule['action'] == 'allow' and rule['source-user']['member'] == 'any':
                linea_dict = {'device':hostname,item_name:item_value,'rule':rule['@name'],'issue':'allow traffic from any source and destination without user'}
                allow_any_source_and_destination.append(linea_dict)
                score = score+1
            else:
                None
        else:
            if (rule['source']['member'] == 'any' and rule['destination']['member'] == 'any') and rule['action'] == 'allow':
                linea_dict = {'device':hostname,item_name:item_value,'rule':rule['@name'],'issue':'allow traffic from any source and destination without user'}
                allow_any_source_and_destination.append(linea_dict)
                score = score+1
            else: None
        # any Application and Action allow
        if rule['application']['member'] == 'any' and rule['action'] == 'allow':
            linea_dict = {'device':hostname,item_name:item_value,'rule':rule['@name'],'issue':'any application and action allow'}
            any_application.append(linea_dict)
            score = score+1
        else:
            None
        # any Service and any Application and Action allow
        if rule['service']['member'] == 'any' and rule['application']['member'] == 'any' and rule['action'] == 'allow':
            linea_dict = {'device':hostname,item_name:item_value,'rule':rule['@name'],'issue':'any application and any service and action allow'}
            any_application_and_service.append(linea_dict)
            score = score+1
        else: None 
        # any in Source or Destination Zone
        if rule['to']['member'] == 'any' or rule['from']['member'] == 'any' and rule['action'] == 'allow':
            linea_dict = {'device':hostname,item_name:item_value,'rule':rule['@name'],'issue':'any source or destination zone and action allow'}
            any_zone.append(linea_dict)
            score = score+1
        else: None 
    rule_score.append({'rule':rule['@name'],item_name:item_value,'score':score})

def create_tables(item_name, item_value):
    security_rules_table = [x for x in security_rules if x[item_name] == item_value]
    no_log_end_table = [x for x in no_log_end if x[item_name] == item_value]
    no_log_setting_table = [x for x in no_log_setting if x[item_name] == item_value]
    no_security_profile_table = [x for x in no_security_profile if x[item_name] == item_value]
    allow_any_source_or_destination_table = [x for x in allow_any_source_or_destination if x[item_name] == item_value]
    allow_any_source_and_destination_table = [x for x in allow_any_source_and_destination if x[item_name] == item_value]
    any_application_table = [x for x in any_application if x[item_name] == item_value]
    any_application_and_service_table = [x for x in any_application_and_service if x[item_name] == item_value]
    any_zone_table = [x for x in any_zone if x[item_name] == item_value]
    disabled_table = [x for x in disabled if x[item_name] == item_value]
    rule_score_table = [x for x in rule_score if x[item_name] == item_value]
    table01 = PrettyTable(['CRITERIO', 'CANTIDAD','%'])
    table01.add_rows(
        [
            ['Total de Reglas de Seguridad',len(security_rules_table),100],
            ['Reglas sin Log at Session End',len(no_log_end_table),round(len(no_log_end_table)*100/len(security_rules_table),2)],
            ['Reglas sin Log Forwarding',len(no_log_setting_table),round(len(no_log_setting_table)*100/len(security_rules_table),2)],
            ['Reglas sin Security Profiles',len(no_security_profile_table),round(len(no_security_profile_table)*100/len(security_rules_table),2)],
            ['Reglas con any en Source o Destination, Action allow y sin usuario',len(allow_any_source_or_destination_table),round(len(allow_any_source_or_destination_table)*100/len(security_rules_table),2)],
            ['Reglas con any en Source y Destination y Action allow y sin usuario',len(allow_any_source_and_destination_table),round(len(allow_any_source_and_destination_table)*100/len(security_rules_table),2)],
            ['Reglas con Application any',len(any_application_table),round(len(any_application_table)*100/len(security_rules_table),2)],
            ['Reglas con Application y Service any',len(any_application_and_service_table),round(len(any_application_and_service_table)*100/len(security_rules_table),2)],
            ['Reglas con Source o Destination Zone any',len(any_zone_table),round(len(any_zone_table)*100/len(security_rules_table),2)],
            ['Reglas Deshabilitadas',len(disabled_table),round(len(disabled_table)*100/len(security_rules_table),2)]
        ]
    )
    table01.align['CRITERIO'] = 'l'
    table01.align['CANTIDAD'] = 'c'
    table01.align['%'] = 'c'
    print(f'[+] {item_value}')
    print(table01)
    sorted_score_list  = sorted(rule_score_table, key=lambda rule_score_dg: rule_score_dg['score'], reverse=True)
    if len(sorted_score_list) >= 10:
        n = 10
    else: n = len(sorted_score_list)
    table02 = PrettyTable(['REGLA','SCORE'])
    for i in range(0,n):
        if sorted_score_list[i]['score'] > 0:
            table02.add_row([sorted_score_list[i]['rule'],sorted_score_list[i]['score']])
    table02.align['REGLA'] = 'l'
    print(table02)
    print('\n')

def main():
    config_file_dict = {}
    if args.t == None:
        print('[-] Error, debe indicar el tipo de análisis (file o api). Intente nuevamente con los parámetros adecuados.')
    else:
        if args.t == 'file':
            try:
                file_name = input('Ingrese el nombre del archivo XML: ')
                open_xml = open(file_name,"r")
                xml_string = open_xml.read()
                config_file_dict = xmltodict.parse(xml_string)
                hostname = config_file_dict['config']['devices']['entry']['deviceconfig']['system']['hostname']
            except Exception as ex:
                print(ex)
        elif args.t == 'api':
            api_host = input('Ingrese la IP o Hostname del dispositivo: ')
            api_username = input('Ingrese el usuario API: ')
            api_password = getpass(prompt='Ingrese la password API: ')
            try:
                api_key = request_api_key(api_host,api_username,api_password)
                if api_key == 'API Key Error':
                    print('[-] Error en la generación de la API key, revise las credenciales e inténtelo nuevamente.')
                else:
                    show_system_info = request_op_get(api_host,'<show><system><info/></system></show>',api_key)
                    if show_system_info == 'Request Error':
                        print('[-] Error en la generación del request. Revise los parámetros e inténtelo nuevamente.')
                    else:
                        hostname = show_system_info['system']['hostname']
                        if 'system-mode' in show_system_info['system'].keys():
                            #isPanorama
                            config_file_dict = request_op_get(api_host,'<show><config><running/></config></show>',api_key)
                            if config_file_dict == 'Request Error':
                                print('[-] Error en la generación del request. Revise los parámetros e inténtelo nuevamente.')
                            else:
                                None
                        else:
                            #isFirewall
                            check_panorama_status = request_op_get(api_host,'<show><panorama-status/></show>',api_key)
                            if check_panorama_status == 'Request Error':
                                print('[-] Error en la generación del request. Revise los parámetros e inténtelo nuevamente.')
                            else:
                                if 'Connected' in check_panorama_status and 'yes' in check_panorama_status:
                                    print('\n[-] El dispositivo está administrado por panorama. Debe lanzar el script contra la ip de panorama.\n')
                                else:
                                    config_file_dict = request_op_get(api_host,'<show><config><running/></config></show>',api_key)
                                    if config_file_dict == 'Request Error':
                                        print('[-] Error en la generación del request. Revise los parámetros e inténtelo nuevamente.')
            except Exception as e:
                        print(e)
        if 'config' in config_file_dict.keys():
            if 'devices' in config_file_dict['config']['mgt-config'].keys():
                device_type = 'panorama'
                print(f'\n[+] Autodetect: {hostname} es {device_type}\n')
                #IsPanorama
                device_groups = config_file_dict['config']['devices']['entry']['device-group']['entry']
                rulebases = ['pre-rulebase','post-rulebase']
                rule_types = ['security','default-security-rules']
                default_flag = 'no'
                for dg in device_groups:
                    for rulebase in rulebases:
                        if rulebase in dg.keys():
                            for rule_type in rule_types:
                                if rule_type in dg[rulebase].keys():
                                    if 'rules' in dg[rulebase][rule_type].keys():
                                        if not dg[rulebase][rule_type]['rules'] == None:
                                            for rule in dg[rulebase][rule_type]['rules']['entry']:
                                                linea_dict_rule_name = {'device':hostname,'rule_name':rule['@name'],'devicegroup':dg['@name']}
                                                security_rules.append(linea_dict_rule_name)
                                                # disabled
                                                if 'disabled' in rule.keys():
                                                    if rule['disabled'] == 'yes':
                                                        linea_dict = {'device':hostname,'devicegroup':dg['@name'],'rule':rule['@name'],'issue':'disabled'}
                                                        disabled.append(linea_dict)
                                                    else:
                                                        if rule_type == 'default-security-rules':
                                                            default_flag = 'yes'
                                                        else:
                                                            default_flag = 'no'
                                                        ruleAnalysis(hostname,'devicegroup',dg['@name'],rule,default_flag)
                                                else:
                                                    if rule_type == 'default-security-rules':
                                                        default_flag = 'yes'
                                                    else:
                                                        default_flag = 'no'
                                                    ruleAnalysis(hostname,'devicegroup',dg['@name'],rule,default_flag)
                    if len(no_log_end) + len(no_log_setting) + len(no_security_profile) + len(allow_any_source_or_destination) + len(allow_any_source_and_destination) + len(any_application) + len(any_application_and_service) + len(any_zone) + len(disabled) > 0:
                        create_tables('devicegroup',dg['@name'])
            else:
                device_type = 'firewall'
                default_flag = 'no'
                print(f'\n[+] Autodetect: {hostname} es {device_type}\n')
                rule_types = ['security','default-security-rules']
                #IsMultiVsys
                if isinstance(config_file_dict['config']['devices']['entry']['vsys']['entry'], list):
                    for vsys in config_file_dict['config']['devices']['entry']['vsys']['entry']:
                        for rule_type in rule_types:
                            for rule in vsys['rulebase'][rule_type]['rules']['entry']:
                                linea_dict_rule_name = {'device':hostname,'rule_name':rule['@name'],'vsys':vsys['@name']}
                                security_rules.append(linea_dict_rule_name)
                                # disabled
                                if 'disabled' in rule.keys():
                                    if rule['disabled'] == 'yes':
                                        linea_dict = {'device':hostname,'vsys':vsys['@name'],'rule':rule['@name'],'issue':'disabled'}
                                        disabled.append(linea_dict)
                                    else:
                                        ruleAnalysis(hostname,'vsys',vsys['@name'],rule,default_flag)
                                else:
                                    if rule_type == 'default-security-rules':
                                        default_flag = 'yes'
                                    else:
                                        default_flag = 'no'
                                    ruleAnalysis(hostname,'vsys',vsys['@name'],rule,default_flag)
                        if len(no_log_end) + len(no_log_setting) + len(no_security_profile) + len(allow_any_source_or_destination) + len(allow_any_source_and_destination) + len(any_application) + len(any_application_and_service) + len(any_zone) + len(disabled) > 0:
                            create_tables('vsys',vsys['@name'])
                #IsSingleVsys
                else:
                    for rule_type in rule_types:
                        for rule in config_file_dict['config']['devices']['entry']['vsys']['entry']['rulebase'][rule_type]['rules']['entry']:
                            vsys_name = config_file_dict['config']['devices']['entry']['vsys']['entry']['@name']
                            linea_dict_rule_name = {'device':hostname,'rule_name':rule['@name'],'vsys':vsys_name}
                            security_rules.append(linea_dict_rule_name)
                            # disabled
                            if 'disabled' in rule.keys():
                                if rule['disabled'] == 'yes':
                                    linea_dict = {'device':hostname,'vsys':vsys_name,'rule':rule['@name'],'issue':'disabled'}
                                    disabled.append(linea_dict)
                                else:
                                    ruleAnalysis(hostname,'vsys',vsys_name,rule,default_flag)
                            else:
                                if rule_type == 'default-security-rules':
                                    default_flag = 'yes'
                                else:
                                    default_flag = 'no'
                                ruleAnalysis(hostname,'vsys',vsys_name,rule,default_flag)
                    if len(no_log_end) + len(no_log_setting) + len(no_security_profile) + len(allow_any_source_or_destination) + len(allow_any_source_and_destination) + len(any_application) + len(any_application_and_service) + len(any_zone) + len(disabled) > 0:
                        create_tables('vsys',vsys_name)
        else:
            print('[-] Archivo de configuración no válido para análisis. Revise los parámetros e inténtelo nuevamente.')



if __name__ == '__main__':
    main()