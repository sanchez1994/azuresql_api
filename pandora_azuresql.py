import os
from datetime import datetime,timedelta
import argparse,sys
import urllib3
from azure.monitor.query import MetricsQueryClient, MetricAggregationType
from azure.identity import DefaultAzureCredential,ClientSecretCredential
from subprocess import *

# provide a cert or disable warnings to run this sample
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

__author__ = "Alejandro Sánchez Carrion"
__copyright__ = "Copyright 2021, PandoraFMS"
__maintainer__ = "Projects department"
__status__ = "Production"
__version__ = "110522"

description= f"""
Azure ver {__version__}

Take data from azureSQL

""" 

# [START metrics_client_auth_with_token_cred]
parser = argparse.ArgumentParser(description= description, formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('-c', '--conf', help='path conf', required=True)
parser.add_argument('--tentacle_port', help='tentacle port', default=41121)
parser.add_argument('--tentacle_address', help='tentacle adress', default=None)
parser.add_argument('--agent_name', help='Name of the agent', default= "Azure_SQL")
parser.add_argument('--prefix_module', help='Prefix module')
parser.add_argument('-g', '--group', help='PandoraFMS destination group (default azure)', default='Azure')
parser.add_argument('--data_dir', help='PandoraFMS data dir (default: /var/spool/pandora/data_in/)', default='/var/spool/pandora/data_in/')
parser.add_argument('--as_agent_plugin', help='mode plugin', default=0,type=int)

args = parser.parse_args()

path_conf=args.conf
name_agent=args.agent_name
as_agent_plugin = args.as_agent_plugin
prefix_module=args.prefix_module

### Pandora Tools ###-------------------------------------------------------------------------------------------------------
modules = []

config = {
    "data_in": args.data_dir,
    "group" : args.group
}

#########################################################################################
# print_agent
#########################################################################################
def print_agent(agent, modules, data_dir="/var/spool/pandora/data_in/", log_modules= None, print_flag = None):
    """Prints agent XML. Requires agent conf (dict) and modules (list) as arguments.
    - Use print_flag to show modules' XML in STDOUT.
    - Returns a tuple (xml, data_file).
    """
    data_file=None

    header = "<?xml version='1.0' encoding='UTF-8'?>\n"
    header += "<agent_data"
    for dato in agent:
        header += " " + str(dato) + "='" + str(agent[dato]) + "'"
    header += ">\n"
    xml = header
    if modules :
        for module in modules:
            modules_xml = print_module(module)
            xml += str(modules_xml)
    if log_modules :
        for log_module in log_modules:
            modules_xml = print_log_module(log_module)
            xml += str(modules_xml)
    xml += "</agent_data>"
    if not print_flag:
        data_file = write_xml(xml, agent["agent_name"], data_dir)
    else:
        print(xml)
    
    return (xml,data_file)

#########################################################################################
# print_module
#########################################################################################
def print_module(module, print_flag=None):
    """Returns module in XML format. Accepts only {dict}.\n
    - Only works with one module at a time: otherwise iteration is needed.
    - Module "value" field accepts str type or [list] for datalists.
    - Use print_flag to show modules' XML in STDOUT.
    """
    data = dict(module)
    module_xml = ("<module>\n"
                  "\t<name><![CDATA[" + str(data["name"]) + "]]></name>\n"
                  "\t<type>" + str(data["type"]) + "</type>\n"
                  )
    
    if type(data["type"]) is not str and "string" not in data["type"]: #### Strip spaces if module not generic_data_string
        data["value"] = data["value"].strip()
    if isinstance(data["value"], list): # Checks if value is a list
        module_xml += "\t<datalist>\n"
        for value in data["value"]:
            if type(value) is dict and "value" in value:
                module_xml += "\t<data>\n"
                module_xml += "\t\t<value><![CDATA[" + str(value["value"]) + "]]></value>\n"
                if "timestamp" in value:
                    module_xml += "\t\t<timestamp><![CDATA[" + str(value["timestamp"]) + "]]></timestamp>\n"
            module_xml += "\t</data>\n"
        module_xml += "\t</datalist>\n"
    else:
        module_xml += "\t<data><![CDATA[" + str(data["value"]) + "]]></data>\n"
    if "desc" in data:
        module_xml += "\t<description><![CDATA[" + str(data["desc"]) + "]]></description>\n"
    if "unit" in data:
        module_xml += "\t<unit><![CDATA[" + str(data["unit"]) + "]]></unit>\n"
    if "interval" in data:
        module_xml += "\t<module_interval><![CDATA[" + str(data["interval"]) + "]]></module_interval>\n"
    if "tags" in data:
        module_xml += "\t<tags>" + str(data["tags"]) + "</tags>\n"
    if "module_group" in data:
        module_xml += "\t<module_group>" + str(data["module_group"]) + "</module_group>\n"
    if "module_parent" in data:
        module_xml += "\t<module_parent>" + str(data["module_parent"]) + "</module_parent>\n"
    if "min_warning" in data:
        module_xml += "\t<min_warning><![CDATA[" + str(data["min_warning"]) + "]]></min_warning>\n"
    if "min_warning_forced" in data:
        module_xml += "\t<min_warning_forced><![CDATA[" + str(data["min_warning_forced"]) + "]]></min_warning_forced>\n"
    if "max_warning" in data:
        module_xml += "\t<max_warning><![CDATA[" + str(data["max_warning"]) + "]]></max_warning>\n"
    if "max_warning_forced" in data:
        module_xml += "\t<max_warning_forced><![CDATA[" + str(data["max_warning_forced"]) + "]]></max_warning_forced>\n"
    if "min_critical" in data:
        module_xml += "\t<min_critical><![CDATA[" + str(data["min_critical"]) + "]]></min_critical>\n"
    if "min_critical_forced" in data:
        module_xml += "\t<min_critical_forced><![CDATA[" + str(data["min_critical_forced"]) + "]]></min_critical_forced>\n"
    if "max_critical" in data:
        module_xml += "\t<max_critical><![CDATA[" + str(data["max_critical"]) + "]]></max_critical>\n"
    if "max_critical_forced" in data:
        module_xml += "\t<max_critical_forced><![CDATA[" + str(data["max_critical_forced"]) + "]]></max_critical_forced>\n"
    if "str_warning" in data:
        module_xml += "\t<str_warning><![CDATA[" + str(data["str_warning"]) + "]]></str_warning>\n"
    if "str_warning_forced" in data:
        module_xml += "\t<str_warning_forced><![CDATA[" + str(data["str_warning_forced"]) + "]]></str_warning_forced>\n"
    if "str_critical" in data:
        module_xml += "\t<str_critical><![CDATA[" + str(data["str_critical"]) + "]]></str_critical>\n"
    if "str_critical_forced" in data:
        module_xml += "\t<str_critical_forced><![CDATA[" + str(data["str_critical_forced"]) + "]]></str_critical_forced>\n"
    if "critical_inverse" in data:
        module_xml += "\t<critical_inverse><![CDATA[" + str(data["critical_inverse"]) + "]]></critical_inverse>\n"
    if "warning_inverse" in data:
        module_xml += "\t<warning_inverse><![CDATA[" + str(data["warning_inverse"]) + "]]></warning_inverse>\n"
    if "max" in data:
        module_xml += "\t<max><![CDATA[" + str(data["max"]) + "]]></max>\n"
    if "min" in data:
        module_xml += "\t<min><![CDATA[" + str(data["min"]) + "]]></min>\n"
    if "post_process" in data:
        module_xml += "\t<post_process><![CDATA[" + str(data["post_process"]) + "]]></post_process>\n"
    if "disabled" in data:
        module_xml += "\t<disabled><![CDATA[" + str(data["disabled"]) + "]]></disabled>\n"
    if "min_ff_event" in data:
        module_xml += "\t<min_ff_event><![CDATA[" + str(data["min_ff_event"]) + "]]></min_ff_event>\n"
    if "status" in data:
        module_xml += "\t<status><![CDATA[" + str(data["status"]) + "]]></status>\n"
    if "timestamp" in data:
        module_xml += "\t<timestamp><![CDATA[" + str(data["timestamp"]) + "]]></timestamp>\n"
    if "custom_id" in data:
        module_xml += "\t<custom_id><![CDATA[" + str(data["custom_id"]) + "]]></custom_id>\n"
    if "critical_instructions" in data:
        module_xml += "\t<critical_instructions><![CDATA[" + str(data["critical_instructions"]) + "]]></critical_instructions>\n"
    if "warning_instructions" in data:
        module_xml += "\t<warning_instructions><![CDATA[" + str(data["warning_instructions"]) + "]]></warning_instructions>\n"
    if "unknown_instructions" in data:
        module_xml += "\t<unknown_instructions><![CDATA[" + str(data["unknown_instructions"]) + "]]></unknown_instructions>\n"
    if "quiet" in data:
        module_xml += "\t<quiet><![CDATA[" + str(data["quiet"]) + "]]></quiet>\n"
    if "module_ff_interval" in data:
        module_xml += "\t<module_ff_interval><![CDATA[" + str(data["module_ff_interval"]) + "]]></module_ff_interval>\n"
    if "crontab" in data:
        module_xml += "\t<crontab><![CDATA[" + str(data["crontab"]) + "]]></crontab>\n"
    if "min_ff_event_normal" in data:
        module_xml += "\t<min_ff_event_normal><![CDATA[" + str(data["min_ff_event_normal"]) + "]]></min_ff_event_normal>\n"
    if "min_ff_event_warning" in data:
        module_xml += "\t<min_ff_event_warning><![CDATA[" + str(data["min_ff_event_warning"]) + "]]></min_ff_event_warning>\n"
    if "min_ff_event_critical" in data:
        module_xml += "\t<min_ff_event_critical><![CDATA[" + str(data["min_ff_event_critical"]) + "]]></min_ff_event_critical>\n"
    if "ff_type" in data:
        module_xml += "\t<ff_type><![CDATA[" + str(data["ff_type"]) + "]]></ff_type>\n"
    if "ff_timeout" in data:
        module_xml += "\t<ff_timeout><![CDATA[" + str(data["ff_timeout"]) + "]]></ff_timeout>\n"
    if "each_ff" in data:
        module_xml += "\t<each_ff><![CDATA[" + str(data["each_ff"]) + "]]></each_ff>\n"
    if "module_parent_unlink" in data:
        module_xml += "\t<module_parent_unlink><![CDATA[" + str(data["parent_unlink"]) + "]]></module_parent_unlink>\n"
    if "global_alerts" in data:
        for alert in data["alert"]:
            module_xml += "\t<alert_template><![CDATA[" + alert + "]]></alert_template>\n"
    module_xml += "</module>\n"

    if print_flag:
        print (module_xml)

    return (module_xml)

#########################################################################################
# write_xml
#########################################################################################

def write_xml(xml, agent_name, data_dir="/var/spool/pandora/data_in/"):
    """Creates a agent .data file in the specified data_dir folder\n
    Args:
    - xml (str): XML string to be written in the file.
    - agent_name (str): agent name for the xml and file name.
    - data_dir (str): folder in which the file will be created."""
    Utime = datetime.now().strftime('%s')
    data_file = "%s/%s.%s.data" %(str(data_dir),agent_name,str(Utime))
    try:
        with open(data_file, 'x') as data:
            data.write(xml)
    except OSError as o:
        sys.exit(f"ERROR - Could not write file: {o}, please check directory permissions")
    except Exception as e:
        sys.exit(f"{type(e).__name__}: {e}")
    return (data_file)

# # default agent
def clean_agent() :
    global agent
    agent = {
        "agent_name"  : "",
        "agent_alias" : "",
        "parent_agent_name" : "",
        "description" : "",
        "version"     : "",
        "os_name"     : "",
        "os_version"  : "",
        "timestamp"   : datetime.today().strftime('%Y/%m/%d %H:%M:%S'),
        #"utimestamp"  : int(datetime.timestamp(datetime.today())),
        "address"     : "",
        "group"       : config["group"],
        "interval"    : "",
        "agent_mode"  : "1",
        }
    return agent

# default module
def clean_module() :
    global modulo
    modulo = {
        "name"   : "",
        "type"   : "generic_data_string",
        "desc"   : "",
        "value"  : "",
    }
    return modulo

#########################################################################################
# tentacle_xml
#########################################################################################
def tentacle_xml(file, tentacle_ops,tentacle_path='', debug=0):
    """Sends file using tentacle protocol\n
    - Only works with one file at time.
    - file variable needs full file path.
    - tentacle_opts should be a dict with tentacle options (address [password] [port]).
    - tentacle_path allows to define a custom path for tentacle client in case is not in sys path).
    - if debug is enabled, the data file will not be removed after being sent.

    Returns 0 for OK and 1 for errors.
    """

    if file is None :
        sys.stderr.write("Tentacle error: file path is required.")
    else :
        data_file = file
    
    if tentacle_ops['address'] is None :
        sys.stderr.write("Tentacle error: No address defined")
        return 1
    
    try :
        with open(data_file, 'r') as data:
            data.read()
        data.close()
    except Exception as e :
        sys.stderr.write(f"Tentacle error: {type(e).__name__} {e}")
        return 1

    tentacle_cmd = f"{tentacle_path}tentacle_client -v -a {tentacle_ops['address']} "
    if "port" in tentacle_ops:
        tentacle_cmd += f"-p {tentacle_ops['port']} "
    if "password" in tentacle_ops:
        tentacle_cmd += f"-x {tentacle_ops['password']} "
    tentacle_cmd += f"{data_file} "

    tentacle_exe=Popen(tentacle_cmd, stdout=PIPE, shell=True)
    rc=tentacle_exe.wait()

    if rc != 0 :
        sys.stderr.write("Tentacle error")
        return 1
    elif debug == 0 : 
        os.remove(file)
 
    return 0

## funcion agent
def agentplugin(modules,agent,plugin_type="server",data_dir="/var/spool/pandora/data_in/",tentacle=False,tentacle_conf=None) :
    if plugin_type == "server":
        for modulo in modules:
            print_module(modulo,1)
        
    elif tentacle == True and tentacle_conf is not None:
        agent_file=print_agent(agent, modules,data_dir)
        if agent_file[1] is not None:
            tentacle_xml(agent_file[1],tentacle_conf)
            print ("1")        
    else:
        print_agent(agent, modules,data_dir)
        print ("1")   

def parse_result(metrics_list,sep="")-> list:
    """
    + Return list containing each line as element
    """    
        
    result=[]

    for line in metrics_list:
        str_line=sep.join(str(elem) for elem in line)
        str_dict={"value":str_line}
        result.append(str_dict)

    return result

f = open(path_conf, "r")
for linea in f:
    if linea == "\n":
        continue
    if '#' in linea:
        continue

    if "tenant_id" in linea:      
        line = linea.split(":")
        tenant_id = line[1].strip()
    if "client_id" in linea:      
        line = linea.split(":")
        client_id = line[1].strip()
    if "secret" in linea:  
        line = linea.split(":")
        secret = line[1].strip()
    if "database_id" in linea:     
        line = linea.split(":")
        database_id = line[1].strip()

credential = ClientSecretCredential(
    tenant_id=tenant_id,
    client_id=client_id,
    client_secret=secret
)

client = MetricsQueryClient(credential)

# [END metrics_client_auth_with_token_cred]


# [START send_metrics_query]

#########-----AZURE SQL-----#########

clean_agent()
agent.update(
    agent_name = name_agent,
    agent_alias= name_agent, 
    description ="Azure SQL database Metrics"  
)  


metrics_uri = database_id

response = client.query_resource(
    metrics_uri,
    metric_names=["cpu_percent"],
    timespan=timedelta(hours=1),
    granularity=timedelta(minutes=5),
    aggregations=[MetricAggregationType.AVERAGE],
    )

metrics_list=[]

for metric in response.metrics:
    for time_series_element in metric.timeseries:
        for metric_value in time_series_element.data:
            metrics_list.append('The cpu_percent at {} is {}'.format(
                metric_value.timestamp,
                metric_value.average
            ))
result_metrics=parse_result(metrics_list)

if result_metrics is not None:
    clean_module()
    modulo.update(
        name = "cpu_percent",
        type = "generic_data_string",
        desc = "CPU percentage",
        value = result_metrics,
    )
    modules.append(modulo)

response = client.query_resource(
    metrics_uri,
    metric_names=["physical_data_read_percent"],
    timespan=timedelta(hours=1),
    granularity=timedelta(minutes=5),
    aggregations=[MetricAggregationType.AVERAGE],
    )

metrics_list=[]

for metric in response.metrics:
    for time_series_element in metric.timeseries:
        for metric_value in time_series_element.data:
            metrics_list.append('The physical_data_read_percent at {} is {}'.format(
                metric_value.timestamp,
                metric_value.average
            ))
result_metrics=parse_result(metrics_list)

if result_metrics is not None:
    clean_module()
    modulo.update(
        name = "physical_data_read_percent",
        type = "generic_data_string",
        desc = "Data IO percentage",
        value = result_metrics,
    )
    modules.append(modulo)

response = client.query_resource(
    metrics_uri,
    metric_names=["log_write_percent"],
    timespan=timedelta(hours=1),
    granularity=timedelta(minutes=5),
    aggregations=[MetricAggregationType.AVERAGE],
    )

metrics_list=[]

for metric in response.metrics:
    for time_series_element in metric.timeseries:
        for metric_value in time_series_element.data:
            metrics_list.append('The log_write_percent at {} is {}'.format(
                metric_value.timestamp,
                metric_value.average
            ))

result_metrics=parse_result(metrics_list)

if result_metrics is not None:
    clean_module()
    modulo.update(
        name = "log_write_percent",
        type = "generic_data_string",
        desc = "Log IO percentage. Not applicable to data warehouses.",
        value = result_metrics,
    )
    modules.append(modulo)

response = client.query_resource(
    metrics_uri,
    metric_names=["storage"],
    timespan=timedelta(hours=1),
    granularity=timedelta(minutes=5),
    aggregations=[MetricAggregationType.AVERAGE],
    )

metrics_list=[]

for metric in response.metrics:
    for time_series_element in metric.timeseries:
        for metric_value in time_series_element.data:
            metrics_list.append('The storage at {} is {}'.format(
                metric_value.timestamp,
                metric_value.average
            ))

result_metrics=parse_result(metrics_list)

if result_metrics is not None:
    clean_module()
    modulo.update(
        name = "storage",
        type = "generic_data_string",
        desc = "Data space used. Not applicable to data warehouses.",
        value = result_metrics,
    )
    modules.append(modulo)

response = client.query_resource(
    metrics_uri,
    metric_names=["connection_successful"],
    timespan=timedelta(hours=1),
    granularity=timedelta(minutes=5),
    aggregations=[MetricAggregationType.AVERAGE],
    )

metrics_list=[]

for metric in response.metrics:
    for time_series_element in metric.timeseries:
        for metric_value in time_series_element.data:
            metrics_list.append('The connection_successful at {} is {}'.format(
                metric_value.timestamp,
                metric_value.average
            ))

result_metrics=parse_result(metrics_list)

if result_metrics is not None:
    clean_module()
    modulo.update(
        name = "connection_successful",
        type = "generic_data_string",
        desc = "Successful Connections",
        value = result_metrics,
    )
    modules.append(modulo)

response = client.query_resource(
    metrics_uri,
    metric_names=["connection_failed"],
    timespan=timedelta(hours=1),
    granularity=timedelta(minutes=5),
    aggregations=[MetricAggregationType.AVERAGE],
    )

metrics_list=[]

for metric in response.metrics:
    for time_series_element in metric.timeseries:
        for metric_value in time_series_element.data:
            metrics_list.append('The connection_failed at {} is {}'.format(
                metric_value.timestamp,
                metric_value.average
            ))

result_metrics=parse_result(metrics_list)

if result_metrics is not None:
    clean_module()
    modulo.update(
        name = "connection_failed",
        type = "generic_data_string",
        desc = "Failed Connections",
        value = result_metrics,
    )
    modules.append(modulo)

response = client.query_resource(
    metrics_uri,
    metric_names=["blocked_by_firewall"],
    timespan=timedelta(hours=1),
    granularity=timedelta(minutes=5),
    aggregations=[MetricAggregationType.AVERAGE],
    )

metrics_list=[]

for metric in response.metrics:
    for time_series_element in metric.timeseries:
        for metric_value in time_series_element.data:
            metrics_list.append('The blocked_by_firewall at {} is {}'.format(
                metric_value.timestamp,
                metric_value.average
            ))

result_metrics=parse_result(metrics_list)

if result_metrics is not None:
    clean_module()
    modulo.update(
        name = "blocked_by_firewall",
        type = "generic_data_string",
        desc = "Blocked by Firewall",
        value = result_metrics,
    )
    modules.append(modulo)

response = client.query_resource(
    metrics_uri,
    metric_names=["deadlock"],
    timespan=timedelta(hours=1),
    granularity=timedelta(minutes=5),
    aggregations=[MetricAggregationType.AVERAGE],
    )

metrics_list=[]

for metric in response.metrics:
    for time_series_element in metric.timeseries:
        for metric_value in time_series_element.data:
            metrics_list.append('The deadlock at {} is {}'.format(
                metric_value.timestamp,
                metric_value.average
            ))

result_metrics=parse_result(metrics_list)

if result_metrics is not None:
    clean_module()
    modulo.update(
        name = "deadlock",
        type = "generic_data_string",
        desc = "Not applicable to data warehouses.",
        value = result_metrics,
    )
    modules.append(modulo)

response = client.query_resource(
    metrics_uri,
    metric_names=["storage_percent"],
    timespan=timedelta(hours=1),
    granularity=timedelta(minutes=5),
    aggregations=[MetricAggregationType.AVERAGE],
    )

metrics_list=[]

for metric in response.metrics:
    for time_series_element in metric.timeseries:
        for metric_value in time_series_element.data:
            metrics_list.append('The storage_percent at {} is {}'.format(
                metric_value.timestamp,
                metric_value.average
            ))

result_metrics=parse_result(metrics_list)

if result_metrics is not None:
    clean_module()
    modulo.update(
        name = "storage_percent",
        type = "generic_data_string",
        desc = "Data space used percent. Not applicable to data warehouses or hyperscale databases.",
        value = result_metrics,
    )
    modules.append(modulo)

response = client.query_resource(
    metrics_uri,
    metric_names=["xtp_storage_percent"],
    timespan=timedelta(hours=1),
    granularity=timedelta(minutes=5),
    aggregations=[MetricAggregationType.AVERAGE],
    )

metrics_list=[]

for metric in response.metrics:
    for time_series_element in metric.timeseries:
        for metric_value in time_series_element.data:
            metrics_list.append('The xtp_storage_percent at {} is {}'.format(
                metric_value.timestamp,
                metric_value.average
            ))

result_metrics=parse_result(metrics_list)

if result_metrics is not None:
    clean_module()
    modulo.update(
        name = "xtp_storage_percent",
        type = "generic_data_string",
        desc = "In-Memory OLTP storage percent. Not applicable to data warehouses.",
        value = result_metrics,
    )
    modules.append(modulo)

response = client.query_resource(
    metrics_uri,
    metric_names=["workers_percent"],
    timespan=timedelta(hours=1),
    granularity=timedelta(minutes=5),
    aggregations=[MetricAggregationType.AVERAGE],
    )

metrics_list=[]

for metric in response.metrics:
    for time_series_element in metric.timeseries:
        for metric_value in time_series_element.data:
            metrics_list.append('The workers_percent at {} is {}'.format(
                metric_value.timestamp,
                metric_value.average
            ))

result_metrics=parse_result(metrics_list)

if result_metrics is not None:
    clean_module()
    modulo.update(
        name = "workers_percent",
        type = "generic_data_string",
        desc = "Workers percentage. Not applicable to data warehouses.",
        value = result_metrics,
    )
    modules.append(modulo)

response = client.query_resource(
    metrics_uri,
    metric_names=["sessions_percent"],
    timespan=timedelta(hours=1),
    granularity=timedelta(minutes=5),
    aggregations=[MetricAggregationType.AVERAGE],
    )

metrics_list=[]

for metric in response.metrics:
    for time_series_element in metric.timeseries:
        for metric_value in time_series_element.data:
            metrics_list.append('The sessions_percent at {} is {}'.format(
                metric_value.timestamp,
                metric_value.average
            ))

result_metrics=parse_result(metrics_list)

if result_metrics is not None:
    clean_module()
    modulo.update(
        name = "sessions_percent",
        type = "generic_data_string",
        desc = "Sessions percentage. Not applicable to data warehouses.",
        value = result_metrics,
    )
    modules.append(modulo)

response = client.query_resource(
    metrics_uri,
    metric_names=["cpu_limit"],
    timespan=timedelta(hours=1),
    granularity=timedelta(minutes=5),
    aggregations=[MetricAggregationType.AVERAGE],
    )

metrics_list=[]

for metric in response.metrics:
    for time_series_element in metric.timeseries:
        for metric_value in time_series_element.data:
            metrics_list.append('The cpu_limit at {} is {}'.format(
                metric_value.timestamp,
                metric_value.average
            ))

result_metrics=parse_result(metrics_list)

if result_metrics is not None:
    clean_module()
    modulo.update(
        name = "cpu_limit",
        type = "generic_data_string",
        desc = "CPU limit. Applies to vCore-based databases.",
        value = result_metrics,
    )
    modules.append(modulo)

response = client.query_resource(
    metrics_uri,
    metric_names=["cpu_used"],
    timespan=timedelta(hours=1),
    granularity=timedelta(minutes=5),
    aggregations=[MetricAggregationType.AVERAGE],
    )

metrics_list=[]

for metric in response.metrics:
    for time_series_element in metric.timeseries:
        for metric_value in time_series_element.data:
            metrics_list.append('The cpu_used at {} is {}'.format(
                metric_value.timestamp,
                metric_value.average
            ))

result_metrics=parse_result(metrics_list)

if result_metrics is not None:
    clean_module()
    modulo.update(
        name = "cpu_used",
        type = "generic_data_string",
        desc = "CPU used. Applies to vCore-based databases.",
        value = result_metrics,
    )
    modules.append(modulo)

response = client.query_resource(
    metrics_uri,
    metric_names=["sqlserver_process_core_percent"],
    timespan=timedelta(hours=1),
    granularity=timedelta(minutes=5),
    aggregations=[MetricAggregationType.AVERAGE],
    )

metrics_list=[]

for metric in response.metrics:
    for time_series_element in metric.timeseries:
        for metric_value in time_series_element.data:
            metrics_list.append('The sqlserver_process_core_percent at {} is {}'.format(
                metric_value.timestamp,
                metric_value.average
            ))

result_metrics=parse_result(metrics_list)

if result_metrics is not None:
    clean_module()
    modulo.update(
        name = "sqlserver_process_core_percent",
        type = "generic_data_string",
        desc = "CPU usage as a percentage of the SQL DB process. Not applicable to data warehouses.",
        value = result_metrics,
    )
    modules.append(modulo)

response = client.query_resource(
    metrics_uri,
    metric_names=["sqlserver_process_memory_percent"],
    timespan=timedelta(hours=1),
    granularity=timedelta(minutes=5),
    aggregations=[MetricAggregationType.AVERAGE],
    )

metrics_list=[]

for metric in response.metrics:
    for time_series_element in metric.timeseries:
        for metric_value in time_series_element.data:
            metrics_list.append('The sqlserver_process_memory_percent at {} is {}'.format(
                metric_value.timestamp,
                metric_value.average
            ))

result_metrics=parse_result(metrics_list)

if result_metrics is not None:
    clean_module()
    modulo.update(
        name = "sqlserver_process_memory_percent",
        type = "generic_data_string",
        desc = "Memory usage as a percentage of the SQL DB process. Not applicable to data warehouses.",
        value = result_metrics,
    )
    modules.append(modulo)

response = client.query_resource(
    metrics_uri,
    metric_names=["tempdb_data_size"],
    timespan=timedelta(hours=1),
    granularity=timedelta(minutes=5),
    aggregations=[MetricAggregationType.AVERAGE],
    )

metrics_list=[]

for metric in response.metrics:
    for time_series_element in metric.timeseries:
        for metric_value in time_series_element.data:
            metrics_list.append('The tempdb_data_size at {} is {}'.format(
                metric_value.timestamp,
                metric_value.average
            ))

result_metrics=parse_result(metrics_list)

if result_metrics is not None:
    clean_module()
    modulo.update(
        name = "tempdb_data_size",
        type = "generic_data_string",
        desc = "Space used in tempdb data files in kilobytes. Not applicable to data warehouses.",
        value = result_metrics,
    )
    modules.append(modulo)

response = client.query_resource(
    metrics_uri,
    metric_names=["tempdb_log_size"],
    timespan=timedelta(hours=1),
    granularity=timedelta(minutes=5),
    aggregations=[MetricAggregationType.AVERAGE],
    )

metrics_list=[]

for metric in response.metrics:
    for time_series_element in metric.timeseries:
        for metric_value in time_series_element.data:
            metrics_list.append('The tempdb_log_size at {} is {}'.format(
                metric_value.timestamp,
                metric_value.average
            ))

result_metrics=parse_result(metrics_list)

if result_metrics is not None:
    clean_module()
    modulo.update(
        name = "tempdb_log_size",
        type = "generic_data_string",
        desc = "Space used in tempdb transaction log file in kilobytes. Not applicable to data warehouses.",
        value = result_metrics,
    )
    modules.append(modulo)

response = client.query_resource(
    metrics_uri,
    metric_names=["tempdb_log_used_percent"],
    timespan=timedelta(hours=1),
    granularity=timedelta(minutes=5),
    aggregations=[MetricAggregationType.AVERAGE],
    )

metrics_list=[]

for metric in response.metrics:
    for time_series_element in metric.timeseries:
        for metric_value in time_series_element.data:
            metrics_list.append('The tempdb_log_used_percent at {} is {}'.format(
                metric_value.timestamp,
                metric_value.average
            ))

result_metrics=parse_result(metrics_list)

if result_metrics is not None:
    clean_module()
    modulo.update(
        name = "tempdb_log_used_percent",
        type = "generic_data_string",
        desc = "Space used percentage in tempdb transaction log file. Not applicable to data warehouses.",
        value = result_metrics,
    )
    modules.append(modulo)

response = client.query_resource(
    metrics_uri,
    metric_names=["app_cpu_billed"],
    timespan=timedelta(hours=1),
    granularity=timedelta(minutes=5),
    aggregations=[MetricAggregationType.AVERAGE],
    )

metrics_list=[]

for metric in response.metrics:
    for time_series_element in metric.timeseries:
        for metric_value in time_series_element.data:
            metrics_list.append('The app_cpu_billed at {} is {}'.format(
                metric_value.timestamp,
                metric_value.average
            ))

result_metrics=parse_result(metrics_list)

if result_metrics is not None:
    clean_module()
    modulo.update(
        name = "app_cpu_billed",
        type = "generic_data_string",
        desc = "App CPU billed. Applies to serverless databases.",
        value = result_metrics,
    )
    modules.append(modulo)

response = client.query_resource(
    metrics_uri,
    metric_names=["app_cpu_percent"],
    timespan=timedelta(hours=1),
    granularity=timedelta(minutes=5),
    aggregations=[MetricAggregationType.AVERAGE],
    )

metrics_list=[]

for metric in response.metrics:
    for time_series_element in metric.timeseries:
        for metric_value in time_series_element.data:
            metrics_list.append('The app_cpu_percent at {} is {}'.format(
                metric_value.timestamp,
                metric_value.average
            ))

result_metrics=parse_result(metrics_list)

if result_metrics is not None:
    clean_module()
    modulo.update(
        name = "app_cpu_percent",
        type = "generic_data_string",
        desc = "App CPU percentage. Applies to serverless databases.",
        value = result_metrics,
    )
    modules.append(modulo)

response = client.query_resource(
    metrics_uri,
    metric_names=["app_memory_percent"],
    timespan=timedelta(hours=1),
    granularity=timedelta(minutes=5),
    aggregations=[MetricAggregationType.AVERAGE],
    )

metrics_list=[]

for metric in response.metrics:
    for time_series_element in metric.timeseries:
        for metric_value in time_series_element.data:
            metrics_list.append('The app_memory_percent at {} is {}'.format(
                metric_value.timestamp,
                metric_value.average
            ))

result_metrics=parse_result(metrics_list)

if result_metrics is not None:
    clean_module()
    modulo.update(
        name = "app_memory_percent",
        type = "generic_data_string",
        desc = "App memory percentage. Applies to serverless databases.",
        value = result_metrics,
    )
    modules.append(modulo)

response = client.query_resource(
    metrics_uri,
    metric_names=["allocated_data_storage"],
    timespan=timedelta(hours=1),
    granularity=timedelta(minutes=5),
    aggregations=[MetricAggregationType.AVERAGE],
    )

metrics_list=[]

for metric in response.metrics:
    for time_series_element in metric.timeseries:
        for metric_value in time_series_element.data:
            metrics_list.append('The allocated_data_storage at {} is {}'.format(
                metric_value.timestamp,
                metric_value.average
            ))

result_metrics=parse_result(metrics_list)

if result_metrics is not None:
    clean_module()
    modulo.update(
        name = "allocated_data_storage",
        type = "generic_data_string",
        desc = "Allocated data storage. Not applicable to data warehouses.",
        value = result_metrics,
    )
    modules.append(modulo)

# response = client.query_resource(
#     metrics_uri,
#     metric_names=["full_backup_size_bytes"],
#     timespan=timedelta(hours=1),
#     granularity=timedelta(minutes=60),
#     aggregations=[MetricAggregationType.AVERAGE],
#     )

# for metric in response.metrics:
#     print(metric.name + ' -- ' + metric.display_description)
#     for time_series_element in metric.timeseries:
#         for metric_value in time_series_element.data:
#             print('full_backup_size_bytes at {} is {}'.format(
#                 metric_value.timestamp,
#                 metric_value.average
#             ))

# response = client.query_resource(
#     metrics_uri,
#     metric_names=["diff_backup_size_bytes"],
#     timespan=timedelta(hours=1),
#     granularity=timedelta(minutes=60),
#     aggregations=[MetricAggregationType.AVERAGE],
#     )

# for metric in response.metrics:
#     print(metric.name + ' -- ' + metric.display_description)
#     for time_series_element in metric.timeseries:
#         for metric_value in time_series_element.data:
#             print('The diff_backup_size_bytes at {} is {}'.format(
#                 metric_value.timestamp,
#                 metric_value.average
#             ))

# response = client.query_resource(
#     metrics_uri,
#     metric_names=["log_backup_size_bytes"],
#     timespan=timedelta(hours=1),
#     granularity=timedelta(minutes=60),
#     aggregations=[MetricAggregationType.AVERAGE],
#     )

# for metric in response.metrics:
#     print(metric.name + ' -- ' + metric.display_description)
#     for time_series_element in metric.timeseries:
#         for metric_value in time_series_element.data:
#             print('The log_backup_size_bytes at {} is {}'.format(
#                 metric_value.timestamp,
#                 metric_value.average
#             ))

# response = client.query_resource(
#     metrics_uri,
#     metric_names=["ledger_digest_upload_success"],
#     timespan=timedelta(hours=1),
#     granularity=timedelta(minutes=5),
#     aggregations=[MetricAggregationType.AVERAGE],
#     )

# for metric in response.metrics:
#     print(metric.name + ' -- ' + metric.display_description)
#     for time_series_element in metric.timeseries:
#         for metric_value in time_series_element.data:
#             print('The ledger_digest_upload_success at {} is {}'.format(
#                 metric_value.timestamp,
#                 metric_value.average
#             ))

# response = client.query_resource(
#     metrics_uri,
#     metric_names=["ledger_digest_upload_failed"],
#     timespan=timedelta(hours=1),
#     granularity=timedelta(minutes=5),
#     aggregations=[MetricAggregationType.AVERAGE],
#     )

# for metric in response.metrics:
#     print(metric.name + ' -- ' + metric.display_description)
#     for time_series_element in metric.timeseries:
#         for metric_value in time_series_element.data:
#             print('The ledger_digest_upload_failed at {} is {}'.format(
#                 metric_value.timestamp,
#                 metric_value.average
#             ))

if args.tentacle_address is not None:
        tentacle_conf={"address":args.tentacle_address,"port":args.tentacle_port}
        agentplugin(modules,agent,"agent",config["data_in"],True,tentacle_conf)
elif as_agent_plugin!=1:
    agentplugin(modules,agent,"agent",config["data_in"]) 
else:
    agentplugin(modules,agent)
