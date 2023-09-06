ResourceMapper = {
    "Data": 0,
    "Access_list": 1,
    "Constraints": 2,
    "History": 3,
    "Subdevice_list": 4,
    "Device_state": 5,
    "Camera_state": 6,
    "Automation_list": 7,
    "Automation_alert_list": 8,
}

RightsMapper = {
    "View": 0,
    "Control_create": 1,
    "Control_remove": 2,
    "Control_whether_collect": 3,
    "Control_use": 4,
    "Control_configure": 5
}

ChannelMapper = {
    'MiHome': 0,
    'MiHome_Guest_Mode': 1,
    'Philips_app': 2,
    'Philips_app_remote_control': 3,
    'Philips_app_remote': 4,
    'HuaWei_Smart_Home': 5,
    'Huawei_Smart_Home_Create_Automation': 6,
    'Timing': 7,
    'google_home_app': 8,
    'google_home_app_Link_third_party': 9
}

ALLUSERS = 0
host = 1
guest = 2
device = 3
