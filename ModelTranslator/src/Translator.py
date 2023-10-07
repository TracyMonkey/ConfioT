import MAPPER
from PromelaGenerator import PromelaGenerator
import os
import json
import re
from optparse import OptionParser

BASE_DIR = os.path.dirname(os.path.abspath(__file__)) + "/"

DEVICE_NAME = ""
DEVICE_RESOURCES = []
DEVICE_POLICIES = {"default": {"Constrains": [], "Policies": []}, "Configurations": []}


def MappingResource(resource: str):
    ret = {
        "id": 0,
    }
    if ("Data" in resource):
        ret["id"] = MAPPER.ResourceMapper["Data"]
        data, user = resource.split("_")
        if (user == "*" or user == "ALLUSERS"):
            ret["user"] = MAPPER.ALLUSERS
        else:
            ret["user"] = eval(f"MAPPER.{user}")
        return ret
    elif ("History" in resource):
        ret["id"] = MAPPER.ResourceMapper["History"]
        data, user = resource.split("_")
        if (user == "*" or user == "ALLUSERS"):
            ret["user"] = MAPPER.ALLUSERS
        else:
            ret["user"] = eval(f"MAPPER.{user}")
        return ret
    else:
        for r in MAPPER.ResourceMapper:
            if (r == resource):
                ret["id"] = MAPPER.ResourceMapper[r]
                return ret

    print("[ERROR]: Wrong Configuration Resource: ", resource)


def MappingChannel(chan: str):
    if (chan == "*"):
        return -1
    for r in MAPPER.ChannelMapper:
        if (r == chan):
            return MAPPER.ChannelMapper[r]
    print("[ERROR]: Wrong Configuration Channel: ", chan)


def ParseSinglePolicy(p: str):
    ret = {"resource": 0, "channel": 0, "user": "", "rights": [], "canBeRevoked": 0}
    policy = re.findall(r'[\w\*]+|\((?:\w+\s*,*\s*)*\)|\d+', p)
    try:
        policy[0] = int(policy[0])
    except Exception:
        policy[0] = MappingResource(policy[0])
    try:
        policy[1] = int(policy[1])
    except Exception:
        policy[1] = MappingChannel(policy[1])

    policy[3] = eval(policy[3])
    if (len(policy) == 5):
        policy[4] = int(policy[4])

    ret["resource"] = policy[0]
    ret["channel"] = policy[1]
    ret["user"] = policy[2]
    ret["rights"] = []
    if (isinstance(policy[3], int)):
        ret["rights"].append(policy[3])
    elif (isinstance(policy[3], tuple) or isinstance(policy[3], list)):
        ret["rights"] += [i for i in policy[3]]
    else:
        print("[ERROR]: Wrong Configuration rights: ", p)

    if (len(policy) == 5):
        ret["canBeRevoked"] = policy[4]

    return ret


def ParsePolicies(config: dict):
    Constrains = []
    Policies = []

    index = 1
    while (True):
        try:
            p = config[f"constrains-{index}"]
            if (p != ''):
                Constrains.append(ParseSinglePolicy(p))
            index += 1
        except Exception:
            break

    index = 1
    while (True):
        try:
            p = config[f"policies-{index}"]
            if (p != ''):
                Policies.append(ParseSinglePolicy(p))
            index += 1
        except Exception:
            break

    return (Constrains, Policies)


def ParseConfigurations(file: str):
    '''
    解析{device_config.json}
    '''

    global DEVICE_NAME, DEVICE_RESOURCES, DEVICE_POLICIES

    # 未处理的config
    config = {}
    with open(file) as f:
        raw_data = f.read()
        config = json.loads(raw_data)

    DEVICE_NAME = config["Device"]
    DEVICE_RESOURCES = [MappingResource(i) for i in config["Resource"]]
    '''
    DEVICE_POLICIES = {
        "default": {
            "Constrains": [],
            "Policies": []
        },
        "Configurations": [{
            "ConfigName": "",
            "Constrains": [],
            "Policies": []
        },]
    }
    '''
    for item in config["Configurations"]:
        if (item["configuration"] == "[default]"):
            Constrains, Policies = ParsePolicies(item)
            DEVICE_POLICIES["default"]["Constrains"] = Constrains
            DEVICE_POLICIES["default"]["Policies"] = Policies
            # print(Constrains, Policies)
        else:
            Constrains, Policies = ParsePolicies(item)
            config_item = {
                "ConfigName": item["configuration"],
                "Params": item["params"],
                "ParamsLen": len(item["params"]),
                "Constrains": Constrains,
                "Policies": Policies,
                "isREVOKE": False,
                "isSHARE": False
            }
            if ("revoke" in item["configuration"].lower()):
                config_item["isREVOKE"] = True
            if ("share" in item["configuration"].lower()):
                config_item["isSHARE"] = True
            DEVICE_POLICIES["Configurations"].append(config_item)


if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("-c", "--configuration", dest="config", help="Configuration File")

    (options, args) = parser.parse_args()

    ParseConfigurations(options.config)

    PG = PromelaGenerator(BASE_DIR, BASE_DIR + f"/../output/{DEVICE_NAME}.pml")
    PG.Generate(DEVICE_NAME, DEVICE_RESOURCES, DEVICE_POLICIES)
    print(DEVICE_NAME)
    print(DEVICE_RESOURCES)
    print(DEVICE_POLICIES)
