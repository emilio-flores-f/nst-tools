/script usage/

(optional args: -type)

List interesting items:
python3 pan_policy_analyzer -file filename.xml -type firewall -list vsys
python3 pan_policy_analyzer -file filename.xml -type panorama -list devicegroup

Analyze all:
python3 pan_policy_analyzer -file filename.xml -type firewall
python3 pan_policy_analyzer -file filename.xml -type panorama

Analyze interesting vsys in firewall type:
python3 pan_policy_analyzer -file filename.xml -type firewall -vsys vsys1

Analyze intereating devicegroup in panorama type
python3 pan_policy_analyzer -file filename.xml -type panorama -devicegroup DG-Test
