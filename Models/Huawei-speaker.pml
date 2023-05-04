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


/******************** Yunmai smart scale *************************/
// Share（Client_A→ Client_B）in “MiHome app” using “member” role 
inline Yunmai_smart_scale_SHARE(user_A, user_B, device_id){
    atomic{
        printf("'Yunmai_smart_scale': Share (user_%d → user_%d) in 'MiHome app' using 'member' role \n", user_A, user_B);

        check_policy_result = false;
        // {resource:1, channel_id:0, user_id, right_id}
        res_need_check.id = 1;
        check_policy(res_need_check, 0, user_A, 1)
        if
            ::  (check_policy_result == true) -> 
                printf("Allow\n")
                // Policy	data[Client_*]	[MiHome]	[Client_B]	[View, Control(create)]   
                Devices[device_id].canBeRevoked[0].id = PolicyNum;             
                Policies[PolicyNum].id = PolicyNum;
                Policies[PolicyNum].resource.id = 0;
                Policies[PolicyNum].resource.data.userId = ALLUSERS;
                Policies[PolicyNum].chans[0].id = 0;
                Policies[PolicyNum].subs[0].id = user_B;
                Policies[PolicyNum].rights[0].id = 0;
                Policies[PolicyNum].rights[1].id = 1;
                PolicyNum = PolicyNum + 1;


                // Policy	AccessList-—MiHome—[user]	[MiHome]	[Client_B]	[View]
                Devices[device_id].canBeRevoked[1].id = PolicyNum;
                Policies[PolicyNum].id = PolicyNum;
                Policies[PolicyNum].resource.id = 1;
                Policies[PolicyNum].chans[0].id = 0;
                Policies[PolicyNum].subs[0].id = user_B;
                Policies[PolicyNum].rights[0].id = 0;
                PolicyNum = PolicyNum + 1;             

                // Policy-x	data[Client_B]	[MiHome—-Guest Mode]	[Client_B]	[Control(whether collect)]
                Devices[device_id].canBeRevoked[2].id = PolicyNum;
                Policies[PolicyNum].id = PolicyNum;
                Policies[PolicyNum].resource.id = 2
                Policies[PolicyNum].chans[0].id = 1;
                Policies[PolicyNum].subs[0].id = user_B;
                Policies[PolicyNum].rights[0].id = 3;
                PolicyNum = PolicyNum + 1;      


                // Then guest can create his personal data after sharing
                Devices[device_id].resources[1].data.isEmpty = false
            :: else ->
                printf("Deny\n") 
        fi;
        
    }
}

// Guest Mode; action={true: ON, false: OFF}
inline Yunmai_smart_scale_GUESTMODE(user_id, device_id, action){
    atomic{
        printf("'Yunmai_smart_scale': user_%d open the Guest Model\n", user_id);
        check_policy_result = false;
        // {resource: constraints, channel_id:1, user_id:user_id, right_id:}
        res_need_check.id = 2;
        check_policy(res_need_check, 1, user_id, -1)
        if
            ::  (check_policy_result == true) -> 
                if
                    :: (action == true) ->
                        printf("Allow\n") 
                        // Policy	data[Client]	[MiHome]	[other users]	None
                        Policies[PolicyNum].id = PolicyNum;
                        Policies[PolicyNum].resource.id = 0;
                        Policies[PolicyNum].resource.data.userId = user_id;
                        Policies[PolicyNum].chans[0].id = 0;
                        i = 0;
                        j = 0;
                        do
                            :: i < MAXUSER ->
                                if
                                    :: (Users[i] != user_id) ->
                                        Policies[PolicyNum].subs[j].id = Users[i];
                                        j = j + 1;
                                    :: else -> skip;
                                fi;
                                i = i + 1;
                            :: else -> break;
                        od;
                        PolicyNum = PolicyNum + 1;                        
                        // TODO: action == false               
                    :: else -> skip;
                        // Policy	data[Client]	[MiHome]	[other users]	[View, Control(create)]

                fi;
            :: else -> printf("Deny\n");
        fi;
    }
}

// REVOKE
inline Yunmai_smart_scale_REVOKE(user_A, user_B, device_id){
    atomic{
        printf("'Yunmai_smart_scale': Revoke (user_%d → user_%d) in 'MiHome app'\n", user_A, user_B);
        check_policy_result = false;
        // {resource:1, channel_id:0, user_id, right_id}
        res_need_check.id = 1;
        check_policy(res_need_check, 0, user_A, 1)
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
    }
}

/******************** Philips Hue bridge *************************/
// Share（Client_A→ Client_B）with “Share Wi-Fi”
inline Philips_bridge_SHARE(user_A, user_B, device_id){
    atomic{
        printf("'Philips_bridge': Share (user_%d → user_%d) with 'Share Wi-Fi' in 'Philips Hue app'\n", user_A, user_B);
 
        // Policy	SubDeviceList; sub_device_state	[(Local)Philips app]	[Client_B]	[View, Control]
        Devices[device_id].canBeRevoked[0].id = PolicyNum;    
        Policies[PolicyNum].id = PolicyNum;
        Policies[PolicyNum].resource.id = 4;
        Policies[PolicyNum].chans[0].id = 2;
        Policies[PolicyNum].subs[0].id = user_B;
        Policies[PolicyNum].rights[0].id = 0;
        Policies[PolicyNum].rights[1].id = 1;
        Policies[PolicyNum].rights[2].id = 2;
        PolicyNum = PolicyNum + 1;        

        Devices[device_id].canBeRevoked[1].id = PolicyNum;    
        Devices[device_id].canChangeState[Devices[device_id].canChangeStateNum].id = PolicyNum
        Devices[device_id].canChangeStateNum = Devices[device_id].canChangeStateNum + 1;
        Policies[PolicyNum].id = PolicyNum;
        Policies[PolicyNum].resource.id = 5;
        Policies[PolicyNum].chans[0].id = 2;
        Policies[PolicyNum].subs[0].id = user_B;
        Policies[PolicyNum].rights[0].id = 0;
        Policies[PolicyNum].rights[1].id = 1;
        Policies[PolicyNum].rights[2].id = 2;
        PolicyNum = PolicyNum + 1;    

        // Policy-x	Constraints	[(Local)Philips app——remote control]	[Client_B]	[Control]
        Devices[device_id].canBeRevoked[2].id = PolicyNum;
        Policies[PolicyNum].id = PolicyNum;
        Policies[PolicyNum].resource.id = 2;
        Policies[PolicyNum].chans[0].id = 3;
        Policies[PolicyNum].subs[0].id = user_B;
        Policies[PolicyNum].rights[0].id = 1;
        Policies[PolicyNum].rights[1].id = 2;
        PolicyNum = PolicyNum + 1;         
    }
}

//Remote Control On (Client)
inline Philips_bridge_REMOTECONTROl_ON(user_id, device_id){
    atomic{
        printf("'Philips_bridge': user_%d open the Remote Control\n", user_id);
        check_policy_result = false;
        // {resource: constraints, channel_id:"(Local)Philips app——remote control", user_id:user_id, right_id:}
        res_need_check.id = 2;
        check_policy(res_need_check, 3, user_id, -1)
        if
            ::  (check_policy_result == true) -> 
                printf("Allow\n");
                // Policy	sub_device_state	[(Remote)Philips app]	[Client]	[View, Control]
                Devices[device_id].canChangeState[Devices[device_id].canChangeStateNum].id = PolicyNum
                Devices[device_id].canChangeStateNum = Devices[device_id].canChangeStateNum + 1;
                Policies[PolicyNum].id = PolicyNum;
                Policies[PolicyNum].resource.id = 5;
                Policies[PolicyNum].chans[0].id = 4;
                Policies[PolicyNum].subs[0].id = user_id;
                Policies[PolicyNum].rights[0].id = 0;
                Policies[PolicyNum].rights[1].id = 1;
                Policies[PolicyNum].rights[2].id = 2;
                PolicyNum = PolicyNum + 1;     

                // Policy	AccessList-—(Remote)Philips app)—[user]	[(Remote)Philips app]	[Client]	[View, Control]
                Policies[PolicyNum].id = PolicyNum;
                Policies[PolicyNum].resource.id = 1;
                Policies[PolicyNum].chans[0].id = 4;
                Policies[PolicyNum].subs[0].id = user_id;
                Policies[PolicyNum].rights[0].id = 0;
                Policies[PolicyNum].rights[1].id = 1;
                Policies[PolicyNum].rights[2].id = 2;
                PolicyNum = PolicyNum + 1;       
            :: else -> 
                printf("Deny\n");
        fi;
    }
}


/******************** Aqara hub *************************/
// Share（Client_A→ Client_B）in “MiHome app” using “member” role
inline Aqara_hub_SHARE(user_A, user_B, device_id){
    atomic{
        printf("'Aqara hub': Share (user_%d → user_%d) in 'MiHome app' using 'member' role \n", user_A, user_B);
                   
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
        Devices[device_id].canChangeState[Devices[device_id].canChangeStateNum].id = PolicyNum
        Devices[device_id].canChangeStateNum = Devices[device_id].canChangeStateNum + 1;
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



    }
}

/******************** Huawei speaker *************************/

// Share（Client_A→ Client_B）in “Huawei Smart Home” using “single device sharing”
inline Huawei_speaker_SHARE(user_A, user_B, device_id){
    atomic{
        printf("'Huawei speaker': Share (user_%d → user_%d) in 'Huawei Smart Home'\n", user_A, user_B);
                   
        // Policy	history[client_*]	[Huawei Smart Home]	[Client_B]	[View, Control]
        Devices[device_id].canBeRevoked[0].id = PolicyNum;  
        Policies[PolicyNum].id = PolicyNum;
        Policies[PolicyNum].resource.id = 3;    
        Policies[PolicyNum].resource.history.userId = ALLUSERS;
        Policies[PolicyNum].chans[0].id = 5;
        Policies[PolicyNum].subs[0].id = user_B;
        Policies[PolicyNum].rights[0].id = 0;
        Policies[PolicyNum].rights[1].id = 1;
        Policies[PolicyNum].rights[2].id = 2;
        PolicyNum = PolicyNum + 1;
        
        
        // Policy	speaker_state (volumn，content)	[HuaWei Smart Home, Huawei speaker]	[Client_B]	[View, Control]
        Devices[device_id].canBeRevoked[1].id = PolicyNum;  
        Devices[device_id].canChangeState[Devices[device_id].canChangeStateNum].id = PolicyNum
        Devices[device_id].canChangeStateNum = Devices[device_id].canChangeStateNum + 1;
        Policies[PolicyNum].id = PolicyNum;
        Policies[PolicyNum].resource.id = 5;    
        Policies[PolicyNum].chans[0].id = 5;
        Policies[PolicyNum].subs[0].id = user_B;
        Policies[PolicyNum].rights[0].id = 0;
        Policies[PolicyNum].rights[1].id = 1;
        Policies[PolicyNum].rights[2].id = 2;
        PolicyNum = PolicyNum + 1;


        //Policy	Constraints	[Huawei Smart Home——Create Automation]	[Client_B]	[Control(create)]
        Devices[device_id].canBeRevoked[2].id = PolicyNum;  
        Policies[PolicyNum].id = PolicyNum;
        Policies[PolicyNum].resource.id = 2;    
        Policies[PolicyNum].chans[0].id = 6;
        Policies[PolicyNum].subs[0].id = user_B;
        Policies[PolicyNum].rights[0].id = 2;
        PolicyNum = PolicyNum + 1;        

    }
}

//Revoke
inline Huawei_speaker_REVOKE(user_A, user_B, device_id){
    atomic{
        printf("'Huawei speaker': Revoke (user_%d → user_%d) in 'Huawei Smart Home'\n", user_A, user_B);
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

    }
}

// Create Automation
inline Huawei_speaker_CREATE_AUTOMATION(user_id, device_id){
    atomic{
        printf("'Huawei speaker': user_%d create Automation\n", user_id);
        check_policy_result = false;
        // {resource:1, channel_id:Huawei Smart Home——Create Automation, user_id, right_id}
        res_need_check.id = 2;
        check_policy(res_need_check, 6, user_id, 1)
        if
            ::  (check_policy_result == true) -> 
                printf("Allow\n")
                // speaker_state (volumn，content)	[Timing]	[Client]	[Control]
                Devices[device_id].canChangeState[Devices[device_id].canChangeStateNum].id = PolicyNum
                Devices[device_id].canChangeStateNum = Devices[device_id].canChangeStateNum + 1;
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


/******************** MiHome smart speaker *************************/
inline MiHome_smart_speaker_SHARE(user_A, user_B, device_id){
    atomic{
        printf("'MiHome smart speaker': Share (user_%d → user_%d) in 'MiHome app'\n", user_A, user_B);
        skip
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
        // :: Yunmai_smart_scale_SHARE(host, guest, Devices[0].id);
        // :: Yunmai_smart_scale_REVOKE(host, guest, Devices[0].id);
        // :: Operation_read_personaldata(host, Devices[0].id);

        // :: 
        //     atomic{
        //         if
        //             :: (COMPETE_Philips_bridge_SHARE == false) ->
        //                 COMPETE_Philips_bridge_SHARE = true;
        //                 Philips_bridge_SHARE(host, guest, Devices[1].id);
        //         fi;
        //     }
        // ::             
        //     atomic{
        //         if
        //             :: (COMPETE_Philips_bridge_REMOTECONTROl_ON == false) ->
        //                 COMPETE_Philips_bridge_REMOTECONTROl_ON = true;
        //                 Philips_bridge_REMOTECONTROl_ON(host, Devices[1].id);
        //         fi;
        //     }
        // :: 
        //     atomic{
        //         if
        //             :: (COMPLETE_Operation_read_accesslist == false) ->
        //                 COMPLETE_Operation_read_accesslist = true;
        //                 Operation_read_accesslist(host, Devices[1].id);
        //         fi;
        //     }


        // :: 
        //     atomic{
        //         if
        //             :: (COMPETE_Philips_bridge_SHARE == false) ->
        //                 COMPETE_Philips_bridge_SHARE = true;
        //                 Aqara_hub_SHARE(host, guest, Devices[2].id);
        //         fi;
        //     }


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


        // :: 
        //     atomic{
        //         Operation_control_subdevicelist(guest, Devices[2].id);
        //     }


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


        ///////////////////////
        // MiHome smart speaker
        ///////////////////////
        Devices[4].id = 4;
        Devices[4].resources[0].id = 5;

        /******************** Default Policies *************************/
        // ///////////////////////
        // // Yunmai smart scale
        // ///////////////////////
        // // DefaultPolicy	data[Client_*] [MiHome]	[Client_owner]	[View, Control(create)]
        // Policies[PolicyNum].id = PolicyNum;
        // Policies[PolicyNum].resource.id = 0;    
        // Policies[PolicyNum].resource.data.userId = ALLUSERS;
        // Policies[PolicyNum].chans[0].id = 0;
        // Policies[PolicyNum].subs[0].id = host;
        // Policies[PolicyNum].rights[0].id = 0;
        // Policies[PolicyNum].rights[1].id = 1;
        // PolicyNum = PolicyNum + 1;

        // // DefaultPolicy	AccessList-—MiHome—[user]	[MiHome]	[Client_owner]	[View, Control]
        // Policies[PolicyNum].id = PolicyNum;
        // Policies[PolicyNum].resource.id = 1;
        // Policies[PolicyNum].chans[0].id = 0;
        // Policies[PolicyNum].subs[0].id = host;
        // Policies[PolicyNum].rights[0].id = 0;
        // Policies[PolicyNum].rights[1].id = 1;
        // Policies[PolicyNum].rights[2].id = 2;
        // PolicyNum = PolicyNum + 1;


        ///////////////////////
        // Philips hue brdige
        ///////////////////////
        // // DefaultPolicy	SubDeviceList	[(Local)Philips app]	[Client_owner]	[View, Control]
        // Policies[PolicyNum].id = PolicyNum;
        // Policies[PolicyNum].resource.id = 4;
        // Policies[PolicyNum].chans[0].id = 2;
        // Policies[PolicyNum].subs[0].id = host;
        // Policies[PolicyNum].rights[0].id = 0;
        // Policies[PolicyNum].rights[1].id = 1;
        // Policies[PolicyNum].rights[2].id = 2;
        // PolicyNum = PolicyNum + 1;        
        // // DefaultPolicy	sub_device_state	[(Local)Philips app]	[Client_owner]	[View, Control]
        // Devices[1].canChangeState[Devices[1].canChangeStateNum].id = PolicyNum
        // Devices[1].canChangeStateNum = Devices[1].canChangeStateNum + 1;
        // Policies[PolicyNum].id = PolicyNum;
        // Policies[PolicyNum].resource.id = 5;
        // Policies[PolicyNum].chans[0].id = 2;
        // Policies[PolicyNum].subs[0].id = host;
        // Policies[PolicyNum].rights[0].id = 0;
        // Policies[PolicyNum].rights[1].id = 1;
        // Policies[PolicyNum].rights[2].id = 2;
        // PolicyNum = PolicyNum + 1;     


        // // Policy-x	Constraints	[(Local)Philips app——remote control]	[Client_owner]
        // Policies[PolicyNum].id = PolicyNum;
        // Policies[PolicyNum].resource.id = 2;
        // Policies[PolicyNum].chans[0].id = 3;
        // Policies[PolicyNum].subs[0].id = host;
        // Policies[PolicyNum].rights[0].id = 1;
        // Policies[PolicyNum].rights[1].id = 2;
        // PolicyNum = PolicyNum + 1;   

        // // DefaultPolicy	Accesslist	[(Local)Philips app]	[Client_owner]	[View, Control]
        // Policies[PolicyNum].id = PolicyNum;
        // Policies[PolicyNum].resource.id = 1;
        // Policies[PolicyNum].chans[0].id = 2;
        // Policies[PolicyNum].subs[0].id = host;
        // Policies[PolicyNum].rights[0].id = 0;
        // Policies[PolicyNum].rights[1].id = 1;
        // Policies[PolicyNum].rights[2].id = 2;
        // PolicyNum = PolicyNum + 1;       


        // ///////////////////////
        // // Aqara hub
        // ///////////////////////
        
        // // DefaultPolicy	SubDeviceList	[Client_owner]	[View, Control]
        // Policies[PolicyNum].id = PolicyNum;
        // Policies[PolicyNum].resource.id = 4;
        // Policies[PolicyNum].chans[0].id = 0;
        // Policies[PolicyNum].subs[0].id = host;
        // Policies[PolicyNum].rights[0].id = 0;
        // Policies[PolicyNum].rights[1].id = 1;
        // Policies[PolicyNum].rights[2].id = 2;
        // PolicyNum = PolicyNum + 1;    
        
        
        // // DefaultPolicy sub_device_state	[MiHome]    [Client_owner]	[View, Control]
        // Devices[2].canChangeState[Devices[2].canChangeStateNum].id = PolicyNum
        // Devices[2].canChangeStateNum = Devices[2].canChangeStateNum + 1;
        // Policies[PolicyNum].id = PolicyNum;
        // Policies[PolicyNum].resource.id = 5;
        // Policies[PolicyNum].chans[0].id = 0;
        // Policies[PolicyNum].subs[0].id = host;
        // Policies[PolicyNum].rights[0].id = 0;
        // Policies[PolicyNum].rights[1].id = 1;
        // Policies[PolicyNum].rights[2].id = 2;
        // PolicyNum = PolicyNum + 1;  


        // // DefaultPolicy	AccessList-—MiHome—[user]	[MiHome]	[Client_owner]	[View, Control]
        // Policies[PolicyNum].id = PolicyNum;
        // Policies[PolicyNum].resource.id = 1;
        // Policies[PolicyNum].chans[0].id = 0;
        // Policies[PolicyNum].subs[0].id = host;
        // Policies[PolicyNum].rights[0].id = 0;
        // Policies[PolicyNum].rights[1].id = 1;
        // Policies[PolicyNum].rights[2].id = 2;
        // PolicyNum = PolicyNum + 1;  

        
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


        // ///////////////////////
        // // MiHome smart speaker
        // ///////////////////////

        // // DefaultPolicy	camera_state	[MiHome]	[Client_owner]	[View, Control]
        // Devices[4].canChangeState[Devices[4].canChangeStateNum].id = PolicyNum
        // Devices[4].canChangeStateNum = Devices[4].canChangeStateNum + 1;
        // Policies[PolicyNum].id = PolicyNum;
        // Policies[PolicyNum].resource.id = 5;    
        // Policies[PolicyNum].chans[0].id = 0;
        // Policies[PolicyNum].subs[0].id = host;
        // Policies[PolicyNum].rights[0].id = 0;
        // Policies[PolicyNum].rights[1].id = 1;
        // Policies[PolicyNum].rights[2].id = 2;
        // PolicyNum = PolicyNum + 1;
        
    }
    // host: {userId = 1}
    run ProcessHost(); 
    // guest: {userId = 2}
    run ProcessGuest(); 
}