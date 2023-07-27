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

typedef PolicyChangeState{
    short id = -1;
}
// Device
typedef Device{
    short id = -1;
    short canBeRevokedNum = 0;
    short canChangeStateNum = 0;
    PolicyBeRevoked canBeRevoked[MAXPOLICY];
    PolicyChangeState canChangeState[MAXPOLICY];
    Resource resources[MAXRESOURCE];
}

short Users[MAXUSER];
// ALL resources
Device Devices[MAXDEVICE];
// Policies will be traversed from the last one (latest) to the first one
Policy Policies[MAXPOLICY];

short PolicyNum = 0;

bool HasBeenRevoked = false;

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
                            :: (Policies[m].banned == true) -> goto NEXTPOLICY_1;
                            :: (Policies[m].resource.id != 2) -> goto NEXTPOLICY_1;
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
                            :: (Policies[m].banned == true) -> goto NEXTPOLICY_2;
                            :: (Policies[m].resource.id == _res.id) ->
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

/******************** Mihome camera *************************/
// SHARE
inline Mihome_camera_SHARE(user_A, user_B, device_id){
    atomic{
        printf("'Mihome_camera': Share (user_%d → user_%d) in 'Mihome app' using 'shared user' role \n", user_A, user_B);

        check_policy_result = false;
        res_need_check.id = 1;
        check_policy(res_need_check, Mihome, user_A, 1)
        if
            ::  (check_policy_result == true) ->
                printf("Allow\n")
                // p3 + (device status: 5; Mihome: 3; guest: 2; view, control(use): 0, 4)
                // Devices[device_id].canBeRevoked[0].id = PolicyNum;
                Policies[PolicyNum].id = PolicyNum;
                Policies[PolicyNum].resource.id = 5;
                Policies[PolicyNum].resource.history.userId = ALLUSERS;
                Policies[PolicyNum].chans[0].id = Mihome;
                Policies[PolicyNum].subs[0].id = user_B;
                Policies[PolicyNum].rights[0].id = 0;
                Policies[PolicyNum].rights[1].id = 4;
                PolicyNum = PolicyNum + 1;

                // // Policy	AccessList-Mihome-[user]	[Mihome]	[Client_B]	[View, Control(collect)]            // ?
                // Devices[device_id].canBeRevoked[1].id = PolicyNum;
                // Policies[PolicyNum].id = PolicyNum;
                // Policies[PolicyNum].resource.id = 1;
                // Policies[PolicyNum].chans[0].id = Mihome;
                // Policies[PolicyNum].subs[0].id = user_B;
                // Policies[PolicyNum].rights[0].id = 0;
                // Policies[PolicyNum].rights[1].id = 3;
                // PolicyNum = PolicyNum + 1;

                // check p4 (3,3,1,6)
                check_policy_result = false;
                res_need_check.id = 3;
                check_policy(res_need_check, Mihome, user_A, 6);
                if
                    ::  (check_policy_result == true) ->
                        printf("Allow p5\n");

                        // p5 + (history: 3; Mihome: 3; guest: 1; view, control(collect): 0, 3)
                        Policies[PolicyNum].id = PolicyNum;
                        Policies[PolicyNum].resource.id = 3; // history
                        Policies[PolicyNum].resource.history.userId = ALLUSERS;
                        Policies[PolicyNum].chans[0].id = Mihome;
                        Policies[PolicyNum].subs[0].id = user_B;
                        Policies[PolicyNum].rights[0].id = 3;
                        PolicyNum = PolicyNum + 1;

                    :: else ->
                        printf("Deny p5\n")
                fi;

                // check p6 (3,3,0,0)
                check_policy_result = false;
                res_need_check.id = 3;
                check_policy(res_need_check, Mihome, user_A, 0);
                if
                    ::  (check_policy_result == true) ->
                        printf("Allow p7\n");

                        // p7 + (history: 3; Mihome: 3; guest: 1; view: 0)
                        Policies[PolicyNum].id = PolicyNum;
                        Policies[PolicyNum].resource.id = 3; // history
                        Policies[PolicyNum].resource.history.userId = ALLUSERS;
                        Policies[PolicyNum].chans[0].id = Mihome;
                        Policies[PolicyNum].subs[0].id = user_B;
                        Policies[PolicyNum].rights[0].id = 0;
                        PolicyNum = PolicyNum + 1;

                        // start recording history
                        Devices[device_id].resources[1].history.isEmpty == false;

                    :: else ->
                        printf("Deny p7\n")
                fi;

            :: else ->
                printf("Deny\n")
        fi;

    }
}

// MOTION DETECTION
inline Mihome_camera_ENABLE_Home_Monitoring(user_id, device_id){
    atomic{
        printf("'Mihome_camera': user_%d enable motion detection in 'Mihome app'\n", user_id);
        check_policy_result = false;
        // check p2(5,3,1,5): whether user can enable motion detection
        res_need_check.id = 5;
        check_policy(res_need_check, Mihome, user_id, 0)
        printf("check result: %d\n", check_policy_result);
        if
            :: (check_policy_result == true) ->
                printf("Allow\n");

                // p4 + (history: 3; Mihome: 3; owner: 1; control(collect), control(remove), control(motionSubConfigure): 2, 3, 6)
                Policies[PolicyNum].id = PolicyNum;
                Policies[PolicyNum].resource.id = 3; // history
                Policies[PolicyNum].resource.history.userId = ALLUSERS;
                Policies[PolicyNum].chans[0].id = Mihome;
                Policies[PolicyNum].subs[0].id = user_id;
                Policies[PolicyNum].rights[0].id = 2;
                Policies[PolicyNum].rights[1].id = 4;
                Policies[PolicyNum].rights[2].id = 6;
                PolicyNum = PolicyNum + 1;


                // check p3 (5,3,2,4): whether guest exists
                check_policy_result = false;
                res_need_check.id = 5;
                check_policy(res_need_check, Mihome, guest, 4);

                printf("check result: %d\n", check_policy_result);


                if
                    :: (check_policy_result == true) ->
                        printf("Allow, create policy for guests.\n");

                        // assert (2==1);

                        // p5 + (history: 3; Mihome: 3; guest: 2; control(collect): 3)
                        Policies[PolicyNum].id = PolicyNum;
                        Policies[PolicyNum].resource.id = 3; // history
                        Policies[PolicyNum].resource.history.userId = ALLUSERS;
                        Policies[PolicyNum].chans[0].id = Mihome;
                        Policies[PolicyNum].subs[0].id = guest;
                        Policies[PolicyNum].rights[0].id = 3;
                        PolicyNum = PolicyNum + 1;



                    :: else ->
                        printf("Deny, no guests. No need to create policy.\n")
                fi;

            :: else ->
                printf("Deny\n")

        fi;
    }
}

// enable alert and sub configures
inline Mihome_camera_ENABLE_PUSH_NOTIFICATIONS(user_id, device_id){
    atomic{
        printf("'Mihome_camera': user_%d enable motion detection conditions in 'Mihome app' \n", user_id);
        printf("Motion detection conditions includes: set time && has at least one zone on && sensitivity > 0. \n");
        // check p4 (3,3,0,6)
        check_policy_result = false;
        res_need_check.id = 3;
        check_policy(res_need_check, Mihome, user_id, 6)
        if
            :: (check_policy_result == true) ->
                printf("Allow\n")

                // p6 + (history: 3; Mihome: 3; owner: 0; view: 0)
                Policies[PolicyNum].id = PolicyNum;
                Policies[PolicyNum].resource.id = 3; // history
                Policies[PolicyNum].resource.history.userId = ALLUSERS;
                Policies[PolicyNum].chans[0].id = Mihome;
                Policies[PolicyNum].subs[0].id = user_id;
                Policies[PolicyNum].rights[0].id = 0;
                PolicyNum = PolicyNum + 1;

                printf("policy num: %d\n", PolicyNum);
                // assert (2==1);

                // check p3 (5,3,1,4): whether guest exists
                check_policy_result = false;
                res_need_check.id = 5;
                check_policy(res_need_check, Mihome, guest, 4)

                if
                    :: (check_policy_result == true) ->
                        printf("Allow, create policy for guests.\n");

                        // p7 + (history: 3; Mihome: 3; guest: 2; view: 0)
                        Policies[PolicyNum].id = PolicyNum;
                        Policies[PolicyNum].resource.id = 3; // history
                        Policies[PolicyNum].resource.history.userId = ALLUSERS;
                        Policies[PolicyNum].chans[0].id = Mihome;
                        Policies[PolicyNum].subs[0].id = guest;
                        Policies[PolicyNum].rights[0].id = 0;
                        PolicyNum = PolicyNum + 1;

                        // start recording history
                        Devices[device_id].resources[1].history.isEmpty == false;

                    :: else ->
                        printf("Deny, no guests. No need to create policy.\n")
                fi;



            :: else ->
                printf("Deny\n")

        fi;
    }
}

//
inline Mihome_camera_delete_history(user_id, device_id){
    atomic{
        printf("'Mihome_camera': user_%d try to delete history in 'Mihome app'\n", user_id);
        printf("Motion detection conditions includes: set time && has at least one zone on && sensitivity > 0. \n");
        // check p6 (3,3,0,0)
        check_policy_result = false;
        res_need_check.id = 3;
        check_policy(res_need_check, Mihome, user_id, 0)
        if
            :: (check_policy_result == true) ->
                printf("Allow\n")

                Devices[device_id].resources[0].history.isEmpty == true;
                Devices[device_id].resources[1].history.isEmpty == true;

            :: else ->
                printf("Deny\n")

        fi;
    }
}


// REVOKE
inline Mihome_camera_REVOKE(user_A, user_B, device_id){
    atomic{
        printf("'Mihome_camera': Revoke (user_%d → user_%d) in 'Mihome app'\n", user_A, user_B);
        // check p1 (1,3,0,1)
        check_policy_result = false;
        res_need_check.id = 1;
        check_policy(res_need_check, Mihome, user_A, 1)
        if
            ::  (check_policy_result == true) ->
                printf("Allow\n")

                // check p3 (5,3,1,0)
                check_policy_result = false;
                res_need_check.id = 5;
                check_policy(res_need_check, Mihome, user_B, 0)
                if
                    ::  (check_policy_result == true) ->
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
                    :: else ->
                        printf("Deny\n")
                fi;

            :: else ->
                printf("Deny\n")
        fi;
    }
}

// read history
inline Operation_view_notifications(user_id, device_id){
    atomic{
        // assert (1==2);
        i = 0;
        do
            :: (i < MAXRESOURCE) ->
                if
                    :: (Devices[device_id].resources[i].id == -1) -> break;
                    :: (Devices[device_id].resources[i].id == 3) ->
                        // assert (1==2);
                        if
                            :: (Devices[device_id].resources[i].history.isEmpty == false) ->
                                printf("user_%d read history of user_%d through 'Mihome app'\n", user_id, Devices[device_id].resources[i].history.userId);
                                check_policy_result = false;
                                // check p7 (3,3,2,0)
                                res_need_check.id = 3;
                                res_need_check.history.userId = Devices[device_id].resources[i].history.userId;
                                check_policy(res_need_check, Mihome, 2 ,0)
                                if
                                    ::  (check_policy_result == true) ->
                                        printf("Allow\n");
                                        printf("test\n");
                                        assert (user_id == Devices[device_id].resources[i].history.userId);
                                        // assert (1==2);
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
                                printf("user_%d read personal data of user_%d through 'MiHome app'\n", user_id, Devices[device_id].resources[i].data.userId);
                                check_policy_result = false;
                                // {resource:0, channel_id:-1, user_id, right_id}
                                res_need_check.id = 0;
                                res_need_check.data.userId = Devices[device_id].resources[i].data.userId;
                                check_policy(res_need_check, -1, user_id, 0)
                                if
                                    ::  (check_policy_result == true) ->
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
        i = 0;
        do
            :: (i < MAXRESOURCE) ->
                if
                    :: (Devices[device_id].resources[i].id == -1) -> break;
                    :: (Devices[device_id].resources[i].id == 1) ->
                        j = Devices[device_id].canChangeStateNum -1;
                        do
                            :: (j >= 0) ->
                                k = 0;
                                do
                                    :: (k < MAXCHANNEL) ->
                                        if
                                            :: (Policies[Devices[device_id].canChangeState[j].id].chans[k].id == -1) -> break;
                                            :: else ->
                                                printf("user_%d read accesslist of channel_%d of device_%d\n", user_id,Policies[Devices[device_id].canChangeState[j].id].chans[k].id, device_id);

                                                check_policy_result = false;
                                                // {resource:1, channel_id: Policies[Devices[device_id].canChangeState[j].id].chans[k].id, user_id, right_id}
                                                res_need_check.id = 1;
                                                check_policy(res_need_check, Policies[Devices[device_id].canChangeState[j].id].chans[k].id, user_id, 0)
                                                if
                                                    ::  (check_policy_result == true) ->
                                                        printf("Allow\n")

                                                    :: else ->
                                                        printf("Deny\n")
                                                        assert (user_id != host);
                                                fi;
                                        fi;
                                        k = k + 1;
                                    :: else -> break;
                                od;
                                j = j - 1;
                            :: else -> break;
                        od;
                    :: else -> skip;
                fi;
                i = i + 1;
            :: else -> break;
        od;

    }
}


inline Operation_control_subdevicelist(user_id, device_id){
    atomic{
        printf("user_%d control SubDeviceList of device_%d\n", user_id, device_id);

        check_policy_result = false;
        // {resource:4, channel_id: mihome, user_id:, right_id: remove}
        res_need_check.id = 4;
        check_policy(res_need_check, 0, user_id, 2)
        if
            ::  (check_policy_result == true) ->
                printf("Allow\n")
                assert(user_id == host);

            :: else ->
                printf("Deny\n")
        fi;

    }
}


inline Operation_After_Revoke(user_id, device_id){
    atomic{
        printf("After Revocation\n", user_id, device_id);

        check_policy_result = false;
        // {resource:state, channel_id: *, user_id:, right_id: control}
        res_need_check.id = 5;
        check_policy(res_need_check, -1, user_id, 1)
        if
            ::  (check_policy_result == true) ->
                printf("Allow\n")
                assert(user_id == host);

            :: else ->
                printf("Deny\n")
        fi;

    }
}



// inline SecurityProperties(user_id){
//     atomic{
//     }

// }


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
    bool COMPETE_Huawei_speaker_SHARE = false;
    bool COMPETE_Huawei_speaker_REVOKE = false;

    do
        ::
            atomic{
                if
                    :: (COMPETE_Huawei_speaker_SHARE == false) ->
                        COMPETE_Huawei_speaker_SHARE = true;
                        Huawei_speaker_SHARE(host, guest, Devices[3].id);
                fi;
            }
        ::
            atomic{
                if
                    :: (COMPETE_Huawei_speaker_REVOKE == false) ->
                        COMPETE_Huawei_speaker_REVOKE = true;
                        Huawei_speaker_REVOKE(host, guest, Devices[3].id);
                fi;
            }
        :: else -> break;
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
    do

        ::
            atomic{
                Huawei_speaker_CREATE_AUTOMATION(guest, Devices[3].id);
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



        ///////////////////////
        // Huawei speaker
        ///////////////////////
        Devices[3].id = 3;
        // host's history
        Devices[3].resources[0].id = 0;
        Devices[3].resources[0].data.userId = host;
        Devices[3].resources[0].data.isEmpty = false;
        // guest's history
        Devices[3].resources[1].id = 0;
        Devices[3].resources[1].data.userId = guest;
        Devices[3].resources[1].data.isEmpty = false;
        Devices[3].resources[2].id = 6;
        Devices[3].resources[3].id = 7;


        // ///////////////////////
        // // Huawei speaker
        // ///////////////////////

        // DefaultPolicy	history[client_*]	[HuaWei Smart Home]	[Client_owner]	[View, Control]
        Policies[PolicyNum].id = PolicyNum;
        Policies[PolicyNum].resource.id = 3;
        Policies[PolicyNum].resource.history.userId = ALLUSERS;
        Policies[PolicyNum].chans[0].id = 5;
        Policies[PolicyNum].subs[0].id = host;
        Policies[PolicyNum].rights[0].id = 0;
        Policies[PolicyNum].rights[1].id = 1;
        Policies[PolicyNum].rights[2].id = 2;
        PolicyNum = PolicyNum + 1;


        // DefaultPolicy	speaker_state (volumn，content)	[HuaWei Smart Home, Huawei speaker]	ALL	[View, Control]
        Devices[3].canChangeState[Devices[3].canChangeStateNum].id = PolicyNum
        Devices[3].canChangeStateNum = Devices[3].canChangeStateNum + 1;
        Policies[PolicyNum].id = PolicyNum;
        Policies[PolicyNum].resource.id = 5;
        Policies[PolicyNum].chans[0].id = 5;
        Policies[PolicyNum].subs[0].id = host;
        Policies[PolicyNum].rights[0].id = 0;
        Policies[PolicyNum].rights[1].id = 1;
        Policies[PolicyNum].rights[2].id = 2;
        PolicyNum = PolicyNum + 1;



    }
    // host: {userId = 1}
    run ProcessHost();
    // guest: {userId = 2}
    run ProcessGuest();
}
