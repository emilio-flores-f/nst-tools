import xmltodict, argparse
from prettytable import PrettyTable

parser = argparse.ArgumentParser()
parser.add_argument("-file", help="Source XML File", type=str, required=True)
parser.add_argument("-type", help="The device is a firewall or panorama", type=str, required=False)
parser.add_argument("-vsys", help="Interesting Vsys", type=str, required=False)
parser.add_argument("-devicegroup", help="Interesting Device-Group", type=str, required=False)
parser.add_argument("-list", help="List interesting items", type=str, required=False)
args = parser.parse_args()

base_file = args.file
device_type = args.type
interesting_dg = args.devicegroup
interesting_vsys = args.vsys
open_xml = open(base_file,"r")
xml_string = open_xml.read()
config_file_dict = xmltodict.parse(xml_string)

hostname = config_file_dict['config']['devices']['entry']['deviceconfig']['system']['hostname']

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

def ruleAnalysis():
    score = 0
    if device_type == 'firewall':
        item_name = 'vsys'
        item_value = vsys_name
    elif device_type == 'panorama':
        item_name = 'devicegroup'
        item_value = dg['@name']
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

def ruleAnalysisDefault():
    score = 0
    if device_type == 'firewall':
        item_name = 'vsys'
        item_value = vsys_name
    elif device_type == 'panorama':
        item_name = 'devicegroup'
        item_value = dg['@name']
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
    rule_score.append({'rule':rule['@name'],item_name:item_value,'score':score})

if args.type == None:
    if 'devices' in config_file_dict['config']['mgt-config'].keys():
        device_type = 'panorama'
    else:
        device_type = 'firewall'

try:
    if args.list == None:
        if device_type == 'firewall':
            if interesting_vsys == None:
                if isinstance(config_file_dict['config']['devices']['entry']['vsys']['entry'], list):
                    for vsys in config_file_dict['config']['devices']['entry']['vsys']['entry']:
                        vsys_name = vsys['@name']
                        for rule in vsys['rulebase']['security']['rules']['entry']:
                            security_rules.append(rule['@name'])
                            # disabled
                            if 'disabled' in rule.keys():
                                if rule['disabled'] == 'yes':
                                    linea_dict = {'device':hostname,'vsys':vsys['@name'],'rule':rule['@name'],'issue':'disabled'}
                                    disabled.append(linea_dict)
                                else:
                                    ruleAnalysis()
                            else:
                                ruleAnalysis()
                        for rule in vsys['rulebase']['default-security-rules']['rules']['entry']: # default rules
                            security_rules.append(rule['@name'])
                            ruleAnalysisDefault()
                else:
                    for rule in config_file_dict['config']['devices']['entry']['vsys']['entry']['rulebase']['security']['rules']['entry']:
                        vsys_name = config_file_dict['config']['devices']['entry']['vsys']['entry']['@name']
                        security_rules.append(rule['@name'])
                        # disabled
                        if 'disabled' in rule.keys():
                            if rule['disabled'] == 'yes':
                                linea_dict = {'device':hostname,'vsys':vsys_name,'rule':rule['@name'],'issue':'disabled'}
                                disabled.append(linea_dict)
                            else:
                                ruleAnalysis()
                        else:
                            ruleAnalysis()
                    for rule in config_file_dict['config']['devices']['entry']['vsys']['entry']['rulebase']['default-security-rules']['rules']['entry']: # default rules
                            security_rules.append(rule['@name'])
                            ruleAnalysisDefault()
                            
            else:
                if isinstance(config_file_dict['config']['devices']['entry']['vsys']['entry'], list):
                    for vsys in config_file_dict['config']['devices']['entry']['vsys']['entry']:
                        vsys_name = vsys['@name']
                        if vsys_name == interesting_vsys:
                            for rule in vsys['rulebase']['security']['rules']['entry']:
                                security_rules.append(rule['@name'])
                                # disabled
                                if 'disabled' in rule.keys():
                                    if rule['disabled'] == 'yes':
                                        linea_dict = {'device':hostname,'vsys':vsys['@name'],'rule':rule['@name'],'issue':'disabled'}
                                        disabled.append(linea_dict)
                                    else:
                                        ruleAnalysis()
                                else:
                                    ruleAnalysis()
                        for rule in vsys['rulebase']['default-security-rules']['rules']['entry']: # default rules
                            if vsys_name == interesting_vsys:
                                security_rules.append(rule['@name'])
                                ruleAnalysisDefault()
                else:
                    for rule in config_file_dict['config']['devices']['entry']['vsys']['entry']['rulebase']['security']['rules']['entry']:
                        vsys_name = config_file_dict['config']['devices']['entry']['vsys']['entry']['@name']
                        if vsys_name == interesting_vsys:
                            security_rules.append(rule['@name'])
                            # disabled
                            if 'disabled' in rule.keys():
                                if rule['disabled'] == 'yes':
                                    linea_dict = {'device':hostname,'vsys':vsys_name,'rule':rule['@name'],'issue':'disabled'}
                                    disabled.append(linea_dict)
                                else:
                                    ruleAnalysis()
                            else:
                                ruleAnalysis()
                    for rule in config_file_dict['config']['devices']['entry']['vsys']['entry']['rulebase']['default-security-rules']['rules']['entry']: # default rules
                        if vsys_name == interesting_vsys:
                            security_rules.append(rule['@name'])
                            ruleAnalysisDefault()
        else:
            if device_type == 'panorama':
                device_group_list = []
                device_groups = config_file_dict['config']['devices']['entry']['device-group']['entry']
                rulebases = ['pre-rulebase','post-rulebase']
                for dg in device_groups:
                    if interesting_dg == None:
                        for rulebase in rulebases:
                            if rulebase in dg.keys():
                                if 'security' in dg[rulebase].keys():
                                    if 'rules' in dg[rulebase]['security'].keys():
                                        if not dg[rulebase]['security']['rules'] == None:
                                            for rule in dg[rulebase]['security']['rules']['entry']:
                                                security_rules.append(rule['@name'])
                                                # disabled
                                                if 'disabled' in rule.keys():
                                                    if rule['disabled'] == 'yes':
                                                        linea_dict = {'device':hostname,'devicegroup':dg['@name'],'rulebase':rulebase,'rule':rule['@name'],'issue':'disabled'}
                                                        disabled.append(linea_dict)
                                                    else:
                                                        ruleAnalysis()
                                                else:
                                                    ruleAnalysis()
                    else:
                        if interesting_dg == dg['@name']:
                            for rulebase in rulebases:
                                if rulebase in dg.keys():
                                    if 'security' in dg[rulebase].keys():
                                        if 'rules' in dg[rulebase]['security'].keys():
                                            if not dg[rulebase]['security']['rules'] == None:
                                                for rule in dg[rulebase]['security']['rules']['entry']:
                                                    security_rules.append(rule['@name'])
                                                    # disabled
                                                    if 'disabled' in rule.keys():
                                                        if rule['disabled'] == 'yes':
                                                            linea_dict = {'device':hostname,'devicegroup':dg['@name'],'rulebase':rulebase,'rule':rule['@name'],'issue':'disabled'}
                                                            disabled.append(linea_dict)
                                                        else:
                                                            ruleAnalysis()
                                                    else:
                                                        ruleAnalysis()
                        else: None
            else:
                print("[-] Debe indicar un tipo de dispositivo válido para analizar.")

        table01 = PrettyTable(['ITEM', 'CANTIDAD','%'])
        table01.add_rows(
            [
            ['Total de Reglas de Seguridad',len(security_rules),100],
            ['Reglas sin Log at Session End',len(no_log_end),round(len(no_log_end)*100/len(security_rules),2)],
            ['Reglas sin Log Forwarding',len(no_log_setting),round(len(no_log_setting)*100/len(security_rules),2)],
            ['Reglas sin Security Profiles',len(no_security_profile),round(len(no_security_profile)*100/len(security_rules),2)],
            ['Reglas con any en Source o Destination, Action allow y sin usuario',len(allow_any_source_or_destination),round(len(allow_any_source_or_destination)*100/len(security_rules),2)],
            ['Reglas con any en Source y Destination y Action allow y sin usuario',len(allow_any_source_and_destination),round(len(allow_any_source_and_destination)*100/len(security_rules),2)],
            ['Reglas con Application any',len(any_application),round(len(any_application)*100/len(security_rules),2)],
            ['Reglas con Application y Service any',len(any_application_and_service),round(len(any_application_and_service)*100/len(security_rules),2)],
            ['Reglas con Source o Destination Zone any',len(any_zone),round(len(any_zone)*100/len(security_rules),2)],
            ['Reglas Deshabilitadas',len(disabled),round(len(disabled)*100/len(security_rules),2)]
            ]
        )
        table01.align['ITEM'] = 'l'
        table01.align['CANTIDAD'] = 'c'
        table01.align['%'] = 'c'
        print(f"\n[+] Análisis de {hostname}:\n")
        print(table01)
        print('\n')
        print('[+] Top Reglas con peor score:\n')
        sorted_score_list  = sorted(rule_score, key=lambda rule_score: rule_score['score'], reverse=True)
        if len(rule_score) >= 10:
            n = 10
        else: n = len(rule_score)
        if device_type == 'firewall':
            table02 = PrettyTable(['REGLA','VSYS','SCORE'])
            for i in range(0,n):
                table02.add_row([sorted_score_list[i]['rule'],sorted_score_list[i]['vsys'],sorted_score_list[i]['score']])
        elif device_type == 'panorama':
            table02 = PrettyTable(['REGLA','DEVICEGROUP','SCORE'])
            for i in range(0,n):
                table02.add_row([sorted_score_list[i]['rule'],sorted_score_list[i]['devicegroup'],sorted_score_list[i]['score']])
            table02.align['DEVICEGROUP'] = 'l'
        table02.align['REGLA'] = 'l'
        print(table02)
        print('\n')

    else:
        if args.list == 'devicegroup' or args.list == 'devicegroups'or args.list == 'device-group' or args.list == 'device-groups':
            if device_type == 'panorama':
                print("\n############### Lista de Device-Groups ###############\n")
                device_groups = config_file_dict['config']['devices']['entry']['device-group']['entry']
                for dg in device_groups:
                    print(f"[+] {dg['@name']}")
                print("\n")
            else:
                print("[-] Parámetros incorrectos, revise e inténtelo nuevamente")
        elif args.list == 'vsys':
            if device_type == 'firewall':
                print("\n############### Lista de Vsys ###############\n")
                if isinstance(config_file_dict['config']['devices']['entry']['vsys']['entry'], list):
                    for vsys in config_file_dict['config']['devices']['entry']['vsys']['entry']:
                        print(f"[+] {vsys['@name']}")
                    print("\n")
                else:
                    print(f"[+] {config_file_dict['config']['devices']['entry']['vsys']['entry']['@name']}")
                    print("\n")
            else:
                print("[-] Parámetros incorrectos, revise e inténtelo nuevamente")
except Exception as e:
    print('\n[-] Parámetros incorrectos, revise e intente nuevamente\n')
    print(e)
