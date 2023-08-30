#define MAXUSER 2
#define MAXCHANNEL 2
#define MAXSUBJECT 2
#define MAXRIGHT 5
#define MAXRESOURCE 20
#define MAXPOLICY 50
#define MAXDEVICE 5

#define ALLUSERS 0
#define host 1
#define guest 2
#define device 3


typedef PersonalData{
    // Personal data is "not" empty at first
    bool isEmpty = 0;
    // Whether the data will be shared between users or not
    bool shared = 0;
    // if userId == ALLUSERS, means the resource includes all users' personal data
    short userId = -1;

}

typedef History{
    // History is "not" empty at first
    bool isEmpty = 0;
    // Whether the data will be shared between users or not
    bool shared = 0;
    // if userId == ALLUSERS, means the resource includes all users' history
    short userId = -1;
}

// 0	data[single user]
// 1	AccessList
// 2 	Constraints
// 3	history[single user]
typedef Resource{
    short id = -1;
    short state = -1;
    PersonalData data;
    History history;
}

/*
0	MiHome
1	MiHome—-Guest Mode
*/
typedef Channel{
    short id = -1;
}

typedef Subject{
    short id = -1;
}

/*
0	View
1	Control (create)
2	Control (remove)
3	Control(whether collect)
*/
typedef Right{
    short id = -1;
}

// Access Rights Policy
typedef Policy{
    bool banned = false;
    short id = -1;
    Resource resource;
    Channel chans[MAXCHANNEL];
    Subject subs[MAXSUBJECT];
    Right rights[MAXRIGHT];
}


typedef PolicyBeRevoked{
    short id = -1;
}

// Device
typedef Device{
    short id = -1;
    short canBeRevokedNum = 0;
    PolicyBeRevoked canBeRevoked[MAXPOLICY];
    Resource resources[MAXRESOURCE];
}

short Users[MAXUSER];
// ALL resources
Device Devices[MAXDEVICE];
// Policies will be traversed from the last one (latest) to the first one
Policy Policies[MAXPOLICY];

short PolicyNum = 0;


// Check the policy constraints
inline check_policy(_res, channel_id, user_id, right_id){
    atomic{
        m = PolicyNum - 1;
        check_policy_result = false;
        if
            :: (_res.id == 2) ->
                // CHECK-1: Check policy with {channel, subject} for "constrants policy" (e.g., [MiHome—-Guest Mode] means the user can use "Guest Mode" operation)
                do
                    :: (m >= 0) ->
                        n = 0;
                        flag_1 = false;
                        flag_2 = false;
                        if
                            :: (Policies[m].id == -1) -> break;
                            :: (Policies[m].id != -1 && Policies[m].banned == true) -> goto NEXTPOLICY_1;
                            :: (Policies[m].id != -1 && Policies[m].resource.id != 2) -> goto NEXTPOLICY_1;
                            :: else -> skip;
                        fi;
                        // check channel_id in the channel list
                        do
                            :: n < MAXCHANNEL ->
                                if
                                    :: (Policies[m].chans[n].id == -1) -> break;
                                    :: (Policies[m].chans[n].id == channel_id) ->
                                        flag_1 = true;
                                        break;
                                    :: else -> skip;
                                fi;
                                n = n + 1;
                            :: else -> break;
                        od;
                        // check the user_id in the subject list
                        o = 0;
                        do
                            :: o < MAXSUBJECT ->
                                if
                                    :: (Policies[m].subs[o].id == -1) -> break;
                                    :: (Policies[m].subs[o].id == user_id) ->
                                        flag_2 = true;
                                        break;
                                    :: else -> skip;
                                fi;
                                o = o + 1;
                            :: else -> break;
                        od;
                        if
                            :: (flag_1 == true && flag_2 == true) ->
                                check_policy_result = true;
                                goto FINISHED;
                            :: else -> skip;
                        fi;
                    NEXTPOLICY_1:
                        m = m - 1;
                    :: else -> break;
                od;
            :: else ->
                // CHECK-2: Check policy with {resource, subject, channel, right}
                m = PolicyNum - 1;
                do
                    :: (m >= 0) ->
                        if
                            :: (Policies[m].id == -1) -> break;
                            :: (Policies[m].id != -1 && Policies[m].banned == true) -> goto NEXTPOLICY_2;
                            :: (Policies[m].id != -1 && Policies[m].banned != true && Policies[m].resource.id == _res.id) ->
                                if
                                    :: (Policies[m].resource.id == 0 && (Policies[m].resource.data.userId == _res.data.userId || Policies[m].resource.data.userId == ALLUSERS)) -> skip;
                                    :: (Policies[m].resource.id == 3 && (Policies[m].resource.history.userId == _res.history.userId || Policies[m].resource.history.userId == ALLUSERS)) -> skip;
                                    :: (Policies[m].resource.id != 0 && Policies[m].resource.id != 3) -> skip;
                                    :: else -> goto NEXTPOLICY_2;
                                fi;

                                n = 0;
                                flag_1 = false;
                                flag_2 = false;
                                flag_3 = false;
                                // check the user_id in the subject list
                                do
                                    :: n < MAXSUBJECT ->
                                        if
                                            :: (Policies[m].subs[n].id == -1) -> break;
                                            :: (Policies[m].subs[n].id == user_id) ->
                                                flag_1 = true;
                                                break;
                                            :: else -> skip;
                                        fi;
                                        n = n + 1;
                                    :: else -> break;
                                od;
                                if

                                    :: (flag_1 == false) -> goto NEXTPOLICY_2
                                    :: else -> skip;
                                fi;
                                // check the channel_id in the channel list
                                o = 0;
                                do
                                    :: o < MAXCHANNEL ->
                                        if
                                            :: (Policies[m].chans[o].id == -1) -> break;
                                            :: (Policies[m].chans[o].id == channel_id) ->
                                                flag_2 = true;
                                                break;
                                            :: else -> skip;
                                        fi;
                                        o = o + 1;
                                    :: else -> break;
                                od;
                                if
                                    // if {channel} = -1, means not check the channel (any channel is ok)
                                    :: (channel_id == -1)  -> flag_2 = true;
                                    :: (flag_2 == false) -> goto NEXTPOLICY_2;
                                    :: else -> skip;
                                fi;
                                // check the right_id in the right list
                                p = 0;
                                do
                                    :: p < MAXRIGHT ->
                                        if
                                            :: (Policies[m].rights[p].id == -1) -> break;
                                            :: (Policies[m].rights[p].id == right_id) ->
                                                flag_3 = true;
                                                break;
                                            :: else -> skip;
                                        fi;
                                        p = p + 1;
                                    :: else -> break;
                                od;
                                if
                                    :: (flag_1 == true && flag_2 == true && flag_3 == true) ->
                                        printf("Check policy: %d\n", m);
                                        check_policy_result = true;
                                        break;
                                    // {resource, subject} matched, but {right} is "empty": means the user can not access the resouce
                                    :: (flag_1 == true && flag_2 == true && Policies[m].rights[0].id == -1) ->
                                        check_policy_result = false;
                                        break;
                                    :: else -> skip;
                                fi;
                            :: else -> skip;
                        fi;
                    NEXTPOLICY_2:
                        m = m - 1;
                    :: else -> break;
                od;
        fi;


        FINISHED:
            skip;
    }
}


/******************** Aqara hub *************************/
// Share（Client_A→ Client_B）in “MiHome app” using “member” role
inline Aqara_hub_SHARE(user_A, user_B, device_id){
    atomic{

        check_policy_result = false;
        // {resource:1, channel_id:0, user_id, right_id}
        res_need_check.id = 1;
        check_policy(res_need_check, 0, user_A, 1)
        if
            ::  (check_policy_result == true) ->
                printf("'Aqara hub': Share (user_%d → user_%d) in 'MiHome app' using 'member' role \n", user_A, user_B);
                printf("Allow\n")
                        // Policy	SubDeviceList	[MiHome]	[Client_B]	[View, Control]
                        Devices[device_id].canBeRevoked[0].id = PolicyNum;
                        Policies[PolicyNum].id = PolicyNum;
                        Policies[PolicyNum].resource.id = 4;
                        Policies[PolicyNum].chans[0].id = 0;
                        Policies[PolicyNum].subs[0].id = user_B;
                        Policies[PolicyNum].rights[0].id = 0;
                        Policies[PolicyNum].rights[1].id = 1;
                        Policies[PolicyNum].rights[2].id = 2;
                        PolicyNum = PolicyNum + 1;


                        // Policy	sub_device_state	[MiHome]	[Client_B]	[View, Control]
                        Devices[device_id].canBeRevoked[1].id = PolicyNum;
                        Policies[PolicyNum].id = PolicyNum;
                        Policies[PolicyNum].resource.id = 5;
                        Policies[PolicyNum].chans[0].id = 0;
                        Policies[PolicyNum].subs[0].id = user_B;
                        Policies[PolicyNum].rights[0].id = 0;
                        Policies[PolicyNum].rights[1].id = 1;
                        Policies[PolicyNum].rights[2].id = 2;
                        PolicyNum = PolicyNum + 1;


                        // Policy	AccessList-—MiHome—[user]	[MiHome]	[Client_B]	[View]
                        Devices[device_id].canBeRevoked[2].id = PolicyNum;
                        Policies[PolicyNum].id = PolicyNum;
                        Policies[PolicyNum].resource.id = 1;
                        Policies[PolicyNum].chans[0].id = 0;
                        Policies[PolicyNum].subs[0].id = user_B;
                        Policies[PolicyNum].rights[0].id = 0;
                        PolicyNum = PolicyNum + 1;

                        //Policy	data[all]	[MiHome]	[Client_B]	[View]
                        Devices[device_id].canBeRevoked[3].id = PolicyNum;
                        Policies[PolicyNum].id = PolicyNum;
                        Policies[PolicyNum].resource.id = 0;
                        Policies[PolicyNum].resource.data.userId = ALLUSERS;
                        Policies[PolicyNum].chans[0].id = 0;
                        Policies[PolicyNum].subs[0].id = user_B;
                        Policies[PolicyNum].rights[0].id = 0;
                        PolicyNum = PolicyNum + 1;

            :: else ->
                printf("Deny\n")
        fi;

    }
}

// REVOKE
inline Aqara_hub_REVOKE(user_A, user_B, device_id){
    atomic{

        check_policy_result = false;
        // {resource:1, channel_id:0, user_id, right_id}
        res_need_check.id = 1;
        check_policy(res_need_check, 0, user_A, 2)
        if
            ::  (check_policy_result == true) ->
                printf("'Aqara_hub': Revoke (user_%d → user_%d) in 'MiHome app'\n", user_A, user_B);
                printf("Allow\n")
                i = 0;
                do
                    :: (i < MAXPOLICY) ->
                        if
                            :: (Devices[device_id].canBeRevoked[i].id == -1) -> break;
                            :: else ->
                                Policies[Devices[device_id].canBeRevoked[i].id].banned = true;
                        fi;
                        i = i + 1;
                    :: else -> break;
                od;
                Operation_After_Revoke(user_B, device_id)
            :: else ->
                printf("Deny\n")
        fi;
    }
}

// Create Automation
inline Aqara_hub_CREATE_AUTOMATION(user_id, device_id){
    atomic{

        check_policy_result = false;
        // {resource:7, channel_id:Mihome, user_id, right_id}
        res_need_check.id = 7;
        check_policy(res_need_check, 0, user_id, 1)
        if
            ::  (check_policy_result == true) ->
                printf("'Aqara_hub': user_%d create Automation\n", user_id);
                printf("Allow\n")
                // speaker_state (volumn，content)	[Timing]	[Client]	[Control]
                Policies[PolicyNum].id = PolicyNum;
                Policies[PolicyNum].resource.id = 5;
                Policies[PolicyNum].chans[0].id = 7;
                Policies[PolicyNum].subs[0].id = user_id;
                Policies[PolicyNum].rights[0].id = 1;
                Policies[PolicyNum].rights[1].id = 2;
                PolicyNum = PolicyNum + 1;
            :: else -> printf("Deny\n");
        fi;
    }
}


// Create Automation
inline Aqara_hub_CREATE_AUTOMATION_alert(user_id, device_id){
    atomic{

        check_policy_result = false;
        // {resource:1, channel_id:Mihome, user_id, right_id}
        res_need_check.id = 8;
        check_policy(res_need_check, 0, user_id, 1)
        if
            ::  (check_policy_result == true) ->
                printf("'Aqara_hub': user_%d create Automation of alert\n", user_id);
                printf("Allow\n")
                // alert personal data	[Timing]	[Client]	[Control]
                Policies[PolicyNum].id = PolicyNum;
                Policies[PolicyNum].resource.id = 0;
                Policies[PolicyNum].chans[0].id = 7;
                Policies[PolicyNum].subs[0].id = device;
                Policies[PolicyNum].rights[0].id = 1;
                Policies[PolicyNum].rights[1].id = 2;
                PolicyNum = PolicyNum + 1;
            :: else -> printf("Deny\n");
        fi;
    }
}


/******************** OPERATIONS *************************/

inline Operation_read_personaldata(user_id, device_id){
    atomic{
        i = 0;
        do
            :: (i < MAXRESOURCE) ->
                if
                    :: (Devices[device_id].resources[i].id == -1) -> break;
                    :: (Devices[device_id].resources[i].id == 0) ->
                        if
                            :: (Devices[device_id].resources[i].data.isEmpty == false) ->

                                check_policy_result = false;
                                // {resource:0, channel_id:-1, user_id, right_id}
                                res_need_check.id = 0;
                                res_need_check.data.userId = Devices[device_id].resources[i].data.userId;
                                check_policy(res_need_check, -1, user_id, 0)
                                if
                                    ::  (check_policy_result == true) ->
                                    printf("user_%d read personal data of user_%d through 'MiHome app'\n", user_id, Devices[device_id].resources[i].data.userId);
                                        printf("Allow\n")
                                        assert (user_id == Devices[device_id].resources[i].data.userId);
                                    :: else ->
                                        printf("Deny\n")
                                fi;
                            :: else -> skip;
                        fi;
                    :: else -> skip;
                fi;
                i = i + 1;
            :: else -> break;
        od;

    }
}

inline Operation_read_accesslist(user_id, device_id){
    atomic{
        check_policy_result = false;
        // {resource:1, channel_id:*, user_id, right_id}
        res_need_check.id = 1;
        check_policy(res_need_check, -1, user_id, 0)
        if
            ::  (check_policy_result == true) ->
                printf("user_%d read accesslist of channel_%d of device_%d\n", user_id, , device_id);

                printf("Allow\n")
                assert (user_id == host);

            :: else ->
                printf("Deny\n")

        fi;

    }
}


inline Operation_control_subdevicelist(user_id, device_id){
    atomic{

        check_policy_result = false;
        // {resource:4, channel_id: mihome, user_id:, right_id: remove}
        res_need_check.id = 4;
        check_policy(res_need_check, 0, user_id, 2)
        if
            ::  (check_policy_result == true) ->
            printf("user_%d control SubDeviceList of device_%d\n", user_id, device_id);
                printf("Allow\n")
                assert(user_id == host);

            :: else ->
                printf("Deny\n")
        fi;

    }
}

// Property: user_B should not be able to control the device after revocation
inline Operation_After_Revoke(user_id, device_id){
    atomic{


        check_policy_result = false;
        // {resource:state, channel_id: *, user_id:, right_id: view}
        res_need_check.id = 5;
        check_policy(res_need_check, -1, user_id, 0)
        if
            ::  (check_policy_result == true) ->
                printf("After Revocation\n", user_id, device_id);
                printf("Allow\n")
                assert(user_id == host);

            :: else ->
                printf("Deny\n")
        fi;

    }
}

// device record alert data
inline Operation_Add_alert_data(user_id, device_id){
    atomic{


        check_policy_result = false;
        res_need_check.id = 0;
        check_policy(res_need_check, -1, device, 1)
        if
            ::  (check_policy_result == true) ->
            printf("Record alert data\n", user_id, device_id);
                printf("Allow\n")
                i = 0;
                do
                    :: (i < MAXRESOURCE) ->
                        if
                            :: (Devices[device_id].resources[i].id == -1) -> break;
                            :: (Devices[device_id].resources[i].id == 0) ->
                                if
                                    :: (Devices[device_id].resources[i].data.isEmpty == true) ->
                                        Devices[device_id].resources[i].data.isEmpty = false
                                    :: else -> skip;
                                fi;
                            :: else -> skip;
                        fi;
                        i = i + 1;
                    :: else -> break;
                od;

            :: else ->
                printf("Deny\n")
        fi;

    }
}



proctype ProcessHost(){
    int i = 0;
    int j = 0;
    int k = 0;
    int l = 0;


    int m = 0;
    int n = 0;
    int o = 0;
    int p = 0;

    bool flag_1 = false;
    bool flag_2 = false;
    bool flag_3 = false;

    bool check_policy_result = false;
    Resource res_need_check;

    bool COMPETE_Philips_bridge_SHARE = false;
    bool COMPETE_Philips_bridge_REMOTECONTROl_ON = false;
    bool COMPLETE_Operation_read_accesslist = false;
    bool COMPETE_Aqara_hub_SHARE = false;
    bool COMPETE_Aqara_hub_REVOKE = false;
    bool COMPETE_Aqara_1 = false;
    bool COMPETE_Aqara_2 = false;
    bool COMPETE_Aqara_3 = false;
    bool COMPETE_Aqara_4 = false;

    do
        ::
            atomic{
                if
                    ::(COMPETE_Aqara_hub_SHARE == false) ->
                        COMPETE_Aqara_hub_SHARE = true;
                        Aqara_hub_SHARE(host, guest, Devices[2].id);
                fi;
            }
        ::
            atomic{
                if
                    :: (COMPETE_Aqara_hub_REVOKE == false) ->
                        COMPETE_Aqara_hub_REVOKE = true;
                        Aqara_hub_REVOKE(host, guest, Devices[2].id);
                fi;
            }
        ::
            atomic{
                if
                    :: (COMPETE_Aqara_1 == false) ->
                        COMPETE_Aqara_1 = true;
                        Aqara_hub_CREATE_AUTOMATION(host, Devices[2].id);
                fi;

            }
        ::
            atomic{
                if
                    :: (COMPETE_Aqara_2 == false) ->
                        COMPETE_Aqara_2 = true;
                        Aqara_hub_CREATE_AUTOMATION_alert(host, Devices[2].id);
                fi;

            }
        ::
            atomic{
                if
                    :: (COMPETE_Aqara_3 == false) ->
                        COMPETE_Aqara_3 = true;
                        Operation_Add_alert_data(host, Devices[2].id);
                fi;
            }
        ::
            atomic{
                if
                    :: (COMPETE_Aqara_4 == false) ->
                        COMPETE_Aqara_4 = true;
                        Operation_read_personaldata(host, Devices[2].id);
                fi;
            }
    od;
}

proctype ProcessGuest(){
    int i = 0;
    int j = 0;
    int k = 0;
    int l = 0;

    int m = 0;
    int n = 0;
    int o = 0;
    int p = 0;

    bool flag_1 = false;
    bool flag_2 = false;
    bool flag_3 = false;

    bool check_policy_result = false;
    Resource res_need_check;


    bool COMPETE_Philips_bridge_REMOTECONTROl_ON = false;


    bool COMPETE_Aqara_guest_1 = false
    bool COMPETE_Aqara_guest_2 = false
    do
        // :: Yunmai_smart_scale_GUESTMODE(guest, Devices[0].id, true);
        // :: Operation_read_personaldata(guest, Devices[0].id);


        // ::
            // atomic{
            //     if
            //         :: (COMPETE_Philips_bridge_REMOTECONTROl_ON == false) ->
            //             COMPETE_Philips_bridge_REMOTECONTROl_ON = true;
            //             Philips_bridge_REMOTECONTROl_ON(guest, Devices[1].id);
            //     fi;
            // }

        ::
            atomic{
                if
                    :: (COMPETE_Aqara_guest_1 == false) ->
                        COMPETE_Aqara_guest_1 = true;
                        Operation_control_subdevicelist(guest, Devices[2].id);
                fi;
            }
        ::
            atomic{
                if
                    :: (COMPETE_Aqara_guest_2 == false) ->
                        COMPETE_Aqara_guest_2 = true;
                        Operation_read_personaldata(guest, Devices[2].id);
                fi;

            }
        :: else -> break;
    od;

}




init
{
    atomic{

        /******************** Users *************************/
        Users[0] = host;
        Users[1] = guest;



        /******************** Devices *************************/
        ///////////////////////
        // Yunmai smart scale
        ///////////////////////
        Devices[0].id = 0;
        // host's personal data
        Devices[0].resources[0].id = 0;
        Devices[0].resources[0].data.userId = host;
        Devices[0].resources[0].data.isEmpty = false;
        // guest's personal data
        Devices[0].resources[1].id = 0;
        Devices[0].resources[1].data.userId = guest;
        Devices[0].resources[1].data.isEmpty = true;
        // Accesslist
        Devices[0].resources[2].id = 1;


        ///////////////////////
        // Philips hue brdige
        ///////////////////////
        Devices[1].id = 1;
        Devices[1].resources[0].id = 1;
        Devices[1].resources[1].id = 4;
        Devices[1].resources[2].id = 5;


        ///////////////////////
        // Aqara hub
        ///////////////////////
        Devices[2].id = 2;
        Devices[2].resources[0].id = 1;
        Devices[2].resources[1].id = 4;
        Devices[2].resources[2].id = 5;
        // host's personal data
        Devices[2].resources[3].id = 0;
        Devices[2].resources[3].data.userId = host;
        Devices[2].resources[3].data.isEmpty = true;
        // guest's personal data
        Devices[2].resources[4].id = 0;
        Devices[2].resources[4].data.userId = guest;
        Devices[2].resources[4].data.isEmpty = true;


        /******************** Default Policies *************************/


        // ///////////////////////
        // // Aqara hub
        // ///////////////////////

        // DefaultPolicy	SubDeviceList	[Client_owner]	[View, Control]
        Policies[PolicyNum].id = PolicyNum;
        Policies[PolicyNum].resource.id = 4;
        Policies[PolicyNum].chans[0].id = 0;
        Policies[PolicyNum].subs[0].id = host;
        Policies[PolicyNum].rights[0].id = 0;
        Policies[PolicyNum].rights[1].id = 1;
        Policies[PolicyNum].rights[2].id = 2;
        PolicyNum = PolicyNum + 1;


        // DefaultPolicy sub_device_state	[MiHome]    [Client_owner]	[View, Control]
        Devices[2].canChangeState[Devices[2].canChangeStateNum].id = PolicyNum
        Devices[2].canChangeStateNum = Devices[2].canChangeStateNum + 1;
        Policies[PolicyNum].id = PolicyNum;
        Policies[PolicyNum].resource.id = 5;
        Policies[PolicyNum].chans[0].id = 0;
        Policies[PolicyNum].subs[0].id = host;
        Policies[PolicyNum].rights[0].id = 0;
        Policies[PolicyNum].rights[1].id = 1;
        Policies[PolicyNum].rights[2].id = 2;
        PolicyNum = PolicyNum + 1;


        // DefaultPolicy	AccessList-—MiHome—[user]	[MiHome]	[Client_owner]	[View, Control]
        Policies[PolicyNum].id = PolicyNum;
        Policies[PolicyNum].resource.id = 1;
        Policies[PolicyNum].chans[0].id = 0;
        Policies[PolicyNum].subs[0].id = host;
        Policies[PolicyNum].rights[0].id = 0;
        Policies[PolicyNum].rights[1].id = 1;
        Policies[PolicyNum].rights[2].id = 2;
        PolicyNum = PolicyNum + 1;


        // Policy	s [id=7];AutoAlert [id=8]	[MiHome]	[Client_B]	[View]
        Policies[PolicyNum].id = PolicyNum;
        Policies[PolicyNum].resource.id = 7;
        Policies[PolicyNum].chans[0].id = 0;
        Policies[PolicyNum].subs[0].id = host;
        Policies[PolicyNum].rights[0].id = 0;
        Policies[PolicyNum].rights[1].id = 1;
        Policies[PolicyNum].rights[2].id = 2;
        PolicyNum = PolicyNum + 1;

        Policies[PolicyNum].id = PolicyNum;
        Policies[PolicyNum].resource.id = 8;
        Policies[PolicyNum].chans[0].id = 0;
        Policies[PolicyNum].subs[0].id = host;
        Policies[PolicyNum].rights[0].id = 0;
        Policies[PolicyNum].rights[1].id = 1;
        Policies[PolicyNum].rights[2].id = 2;
        PolicyNum = PolicyNum + 1;

        // DefaultPolicy	data[Client_*] [MiHome]	[Client_owner]	[View, Control(create)]
        Policies[PolicyNum].id = PolicyNum;
        Policies[PolicyNum].resource.id = 0;
        Policies[PolicyNum].resource.data.userId = ALLUSERS;
        Policies[PolicyNum].chans[0].id = 0;
        Policies[PolicyNum].subs[0].id = host;
        Policies[PolicyNum].rights[0].id = 0;
        Policies[PolicyNum].rights[1].id = 1;
        PolicyNum = PolicyNum + 1;

    }
    // host: {userId = 1}
    run ProcessHost();
    // guest: {userId = 2}
    run ProcessGuest();
}
