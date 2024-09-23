import xmltodict, argparse, pprint
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
used_security_profiles = []
unused_security_profiles = []
configured_security_profiles = []
security_profile_types = ['virus', 'spyware', 'vulnerability', 'wildfire-analysis', 'file-blocking', 'url-filtering', 'data-filtering']

def ruleAnalysis():
    if device_type == 'firewall':
        item_name = 'vsys'
        item_value = vsys_name
    elif device_type == 'panorama':
        item_name = 'devicegroup'
        item_value = dg['@name']
    if 'profile-setting' in rule.keys():
        if 'group' in rule['profile-setting'].keys():
            if rule['profile-setting']['group'] == None:
                None
            else:
                if 'member' in rule['profile-setting']['group'].keys():
                    if rule['profile-setting']['group'] == None or rule['profile-setting']['group'] == 'None':
                        None
                    else:
                        if rule['profile-setting']['group']['member'] in used_security_profiles:
                            None
                        else:
                            if isinstance(rule['profile-setting']['group']['member'], dict):
                                linea_dict = {'profile_setting_type':'group','spg_name':rule['profile-setting']['group']['member']['#text'], 'location':rule['profile-setting']['group']['member']['@loc']}
                                if linea_dict in used_security_profiles:
                                    None
                                else:
                                    used_security_profiles.append(linea_dict)
                            else:
                                linea_dict = {'profile_setting_type':'group','spg_name':rule['profile-setting']['group']['member'], 'location':'shared'}
                                if linea_dict in used_security_profiles:
                                    None
                                else:
                                    used_security_profiles.append(linea_dict)
                else:
                    None
        elif 'profiles' in rule['profile-setting'].keys():
            if rule['profile-setting']['profiles'] == None or rule['profile-setting']['profiles'] == 'None':
                None
            else:
                for sp in security_profile_types:
                    if sp in rule['profile-setting']['profiles'].keys():
                        if isinstance(rule['profile-setting']['profiles'][sp]['member'], dict):
                            linea_dict = {'profile_setting_type':'profile','security_profile_type':sp,'security_profile_name':rule['profile-setting']['profiles'][sp]['member']['#text'],'location':rule['profile-setting']['profiles'][sp]['member']['@loc']}
                            if linea_dict in used_security_profiles:
                                None
                            else:
                                used_security_profiles.append(linea_dict)
                        else:
                            linea_dict = {'profile_setting_type':'profile','security_profile_type':sp,'security_profile_name':rule['profile-setting']['profiles'][sp]['member'],'location':'shared'}
                            if linea_dict in used_security_profiles:
                                None
                            else:
                                used_security_profiles.append(linea_dict)
    else:
        None

if args.type == None:
    if 'devices' in config_file_dict['config']['mgt-config'].keys():
        device_type = 'panorama'
        #print(f'*Es {device_type}*')
    else:
        device_type = 'firewall'
        #print(f'*Es {device_type}*')

if args.list == None:
    if device_type == 'firewall':
        if 'shared' in config_file_dict['config'].keys():
            if 'profiles' in config_file_dict['config']['shared'].keys():
                for profile_type in security_profile_types:
                    if profile_type in config_file_dict['config']['shared']['profiles']:
                        if isinstance(config_file_dict['config']['shared']['profiles'][profile_type]['entry'], list):
                            for item in config_file_dict['config']['shared']['profiles'][profile_type]['entry']:
                                linea_dict = {'profile_setting_type':'profile','security_profile_type':profile_type,'security_profile_name':item['@name'],'location':'shared'}
                                configured_security_profiles.append(linea_dict)
                        else:
                            linea_dict = {'profile_setting_type':'profile','security_profile_type':profile_type,'security_profile_name':config_file_dict['config']['shared']['profiles'][profile_type]['entry']['@name'],'location':'shared'}
                            configured_security_profiles.append(linea_dict)
            if 'profile-group' in config_file_dict['config']['shared'].keys():
                if isinstance(config_file_dict['config']['shared']['profile-group']['entry'], list):
                    for item in config_file_dict['config']['shared']['profile-group']['entry']:
                        linea_dict = {'profile_setting_type':'group','spg_name':item['@name'], 'location':'shared'}
                        configured_security_profiles.append(linea_dict)
                else:
                    linea_dict = {'profile_setting_type':'group','spg_name':config_file_dict['config']['shared']['profile-group']['entry']['@name'], 'location':'shared'}
                    configured_security_profiles.append(linea_dict)
        if interesting_vsys == None:
            # caso sspp lab, n vsys
            if isinstance(config_file_dict['config']['devices']['entry']['vsys']['entry'], list):
                for vsys in config_file_dict['config']['devices']['entry']['vsys']['entry']:
                    if 'profiles' in vsys.keys():
                        for profile in vsys['profiles']:
                            if profile in security_profile_types:
                                if vsys['profiles'][profile] == None:
                                    None
                                else:
                                    if isinstance(vsys['profiles'][profile]['entry'], list):
                                        for entry in vsys['profiles'][profile]['entry']:
                                            linea_dict = {'profile_setting_type':'profile','security_profile_type':profile,'security_profile_name':entry['@name'],'location':vsys['@name']}
                                            configured_security_profiles.append(linea_dict)
                                    else:
                                        linea_dict = {'profile_setting_type':'profile','security_profile_type':profile,'security_profile_name':vsys['profiles'][profile]['entry']['@name'],'location':vsys['@name']}
                                        configured_security_profiles.append(linea_dict)
                    if 'profile-group' in vsys.keys():
                        if isinstance(vsys['profile-group']['entry'], list):
                            for spg in vsys['profile-group']['entry']:
                                linea_dict = {'profile_setting_type':'group','spg_name':spg['@name'], 'location':vsys['@name']}
                                configured_security_profiles.append(linea_dict)
                        else:
                            linea_dict = {'profile_setting_type':'group','spg_name':vsys['profile-group']['entry']['@name'], 'location':vsys['@name']}
                            configured_security_profiles.append(linea_dict)
                    vsys_name = vsys['@name']
                    # Análisis de Reglas
                    for rule in vsys['rulebase']['security']['rules']['entry']:
                        security_rules.append(rule['@name'])
                        ruleAnalysis()
            # caso cclh, 1 vsys
            else:
                vsys = config_file_dict['config']['devices']['entry']['vsys']['entry']
                if 'profiles' in vsys.keys():
                    vsys = config_file_dict['config']['devices']['entry']['vsys']['entry']
                    for profile in vsys['profiles']:
                        if profile in security_profile_types:
                            if vsys['profiles'][profile] == None:
                                    None
                            else:
                                if isinstance(vsys['profiles'][profile]['entry'], list):
                                    for entry in config_file_dict['config']['devices']['entry']['vsys']['entry']['profiles'][profile]['entry']:
                                        linea_dict = {'profile_setting_type':'profile','security_profile_type':profile,'security_profile_name':entry['@name'],'location':vsys['@name']}
                                        configured_security_profiles.append(linea_dict)
                                else:
                                    linea_dict = {'profile_setting_type':'profile','security_profile_type':profile,'security_profile_name':vsys['@name']['profiles'][profile]['entry']['@name'],'location':vsys['@name']}
                                    configured_security_profiles.append(linea_dict)
                if 'profile-group' in vsys.keys():
                    if isinstance(vsys['profile-group']['entry'], list):
                        for spg in vsys['profile-group']['entry']:
                            linea_dict = {'profile_setting_type':'group','spg_name':spg['@name'], 'location':vsys['@name']}
                            configured_security_profiles.append(linea_dict)
                    else:
                        linea_dict = {'profile_setting_type':'group','spg_name':vsys['profile-group']['entry']['@name'], 'location':vsys['@name']}
                        configured_security_profiles.append(linea_dict)
                # Análisis de Reglas
                for rule in config_file_dict['config']['devices']['entry']['vsys']['entry']['rulebase']['security']['rules']['entry']:
                    vsys_name = config_file_dict['config']['devices']['entry']['vsys']['entry']['@name']
                    security_rules.append(rule['@name'])
                    ruleAnalysis()
        else:
            if isinstance(config_file_dict['config']['devices']['entry']['vsys']['entry'], list):
                for vsys in config_file_dict['config']['devices']['entry']['vsys']['entry']:
                    for profile in vsys['profiles']:
                        print(profile)
                    vsys_name = vsys['@name']
                    if vsys_name == interesting_vsys:
                        for rule in vsys['rulebase']['security']['rules']['entry']:
                            security_rules.append(rule['@name'])
                            ruleAnalysis()
            else:
                for profile in config_file_dict['config']['devices']['entry']['vsys']['entry']['profiles']:
                        print(profile)
                for rule in config_file_dict['config']['devices']['entry']['vsys']['entry']['rulebase']['security']['rules']['entry']:
                    vsys_name = config_file_dict['config']['devices']['entry']['vsys']['entry']['@name']
                    if vsys_name == interesting_vsys:
                        security_rules.append(rule['@name'])
                        ruleAnalysis()
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
                                        if not dg[rulebase]['security']['rules'] == None:
                                            for rule in dg[rulebase]['security']['rules']['entry']:
                                                security_rules.append(rule['@name'])
                                                ruleAnalysis()
                else:
                    if interesting_dg == dg['@name']:
                        for rulebase in rulebases:
                            if rulebase in dg.keys():
                                if 'security' in dg[rulebase].keys():
                                    if 'rules' in dg[rulebase]['security'].keys():
                                        if not dg[rulebase]['security']['rules'] == None:
                                            if not dg[rulebase]['security']['rules'] == None:
                                                for rule in dg[rulebase]['security']['rules']['entry']:
                                                    security_rules.append(rule['@name'])
                                                    ruleAnalysis()
                    else: None
        else:
            print("[-] Debe indicar un tipo de dispositivo válido para analizar.")
    for profile in configured_security_profiles:
        if profile['profile_setting_type'] == 'group':
            if profile in used_security_profiles:
                None
            else:
                unused_security_profiles.append(profile)
        # else:
        #     if profile['profile_setting_type'] == 'profile':
        #         if profile in used_security_profiles:
        #             None
        #         else:
        #             unused_security_profiles.append(profile)
        #     else: None

    print(f"\nConfigured: {configured_security_profiles}\n")
    print(f"Used: {used_security_profiles}\n")
    print(f"Unused Groups: {unused_security_profiles}\n")

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


