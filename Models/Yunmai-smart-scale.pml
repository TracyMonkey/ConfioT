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
// Device
typedef Device{
    short id = -1;
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
        i = PolicyNum - 1;
        check_policy_result = false;
        
        // CHECK-1: Check policy with {channel, subject} for "constrants policy" (e.g., [MiHome—-Guest Mode] means the user can use "Guest Mode" operation)
        do
            :: (i >= 0) ->
                j = 0;
                flag_1 = false;
                flag_2 = false;
                if
                    :: (Policies[i].id == -1) -> break;
                    :: (Policies[i].banned == true) -> goto NEXTPOLICY_1;
                    :: (Policies[i].resource.id != 2) -> break;
                    :: else -> skip;
                fi;
                // check channel_id in the channel list
                do 
                    :: j < MAXCHANNEL ->
                        if
                            :: (Policies[i].chans[j].id == -1) -> break;
                            :: (Policies[i].chans[j].id == channel_id) ->
                                flag_1 = true;
                                break;
                            :: else -> skip;
                        fi;
                        j = j + 1;
                    :: else -> break
                od;
                // check the user_id in the subject list
                j = 0;
                do 
                    :: j < MAXSUBJECT ->
                        if
                            :: (Policies[i].subs[j].id == -1) -> break;
                            :: (Policies[i].subs[j].id == user_id) ->
                                flag_2 = true;
                                break;
                            :: else -> skip;
                        fi;
                        j = j + 1;
                    :: else -> break
                od;
                if
                    :: (flag_1 == true && flag_2 == true) ->
                        check_policy_result = true;
                        goto FINISHED;
                    :: else -> skip;
                fi;
            NEXTPOLICY_1:
                i = i - 1;
            :: else -> break;
        od;
        
        // CHECK-2: Check policy with {resource, subject, right} only
        
        i = PolicyNum - 1;
        do
            :: (i >= 0) ->
                if
                    :: (Policies[i].id == -1) -> break;
                    :: (Policies[i].banned == true) -> goto NEXTPOLICY_2;
                    :: (Policies[i].resource.id == _res.id) ->
                        if
                            :: (Policies[i].resource.id == 0 && (Policies[i].resource.data.userId == _res.data.userId || Policies[i].resource.data.userId == ALLUSERS)) -> skip;                  
                            :: (Policies[i].resource.id == 3 && (Policies[i].resource.history.userId == _res.history.userId || Policies[i].resource.history.userId == ALLUSERS)) -> skip;
                            :: (Policies[i].resource.id != 0 && Policies[i].resource.id != 3) -> skip;
                            :: else -> goto NEXTPOLICY_2;
                        fi;
                        
                        j = 0;
                        flag_1 = false;
                        flag_2 = false;
                        // check the user_id in the subject list
                        do 
                            :: j < MAXSUBJECT ->
                                if
                                    :: (Policies[i].subs[j].id == -1) -> break;
                                    :: (Policies[i].subs[j].id == user_id) ->
                                        flag_1 = true;
                                        break;
                                    :: else -> skip;
                                fi;
                                j = j + 1;
                            :: else -> break
                        od;
                        // check the right_id in the right list
                        j = 0;
                        do 
                            :: j < MAXRIGHT ->
                                if
                                    :: (Policies[i].rights[j].id == -1) -> break;
                                    :: (Policies[i].rights[j].id == right_id) ->
                                        flag_2 = true;
                                        break;
                                    :: else -> skip;
                                fi;
                                j = j + 1;
                            :: else -> break
                        od;                        
                        if
                            
                            :: (flag_1 == true && flag_2 == true) ->
                                check_policy_result = true;
                                break;
                            // {resource, subject} matched, but {right} is "empty": means the user can not access the resouce
                            :: (flag_1 == true && Policies[i].rights[0].id == -1) ->
                                check_policy_result = false;
                                break;
                            :: else -> skip;
                        fi;
                    :: else -> skip;
                fi;
            NEXTPOLICY_2:
                i = i - 1;
            :: else -> break;
        od;   

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
        check_policy_result = false;
        // {resource:, channel_id:1, user_id:user_id, right_id:}
        res_need_check.id = -1;
        check_policy(res_need_check, 1, user_id, -1)
        if
            ::  (check_policy_result == true) -> 
                if
                    :: (action == true) ->
                        printf("'Yunmai_smart_scale': user_%d open the Guest Model of \n", user_id);
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
            :: else -> skip
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
                                // {resource:0, channel_id:0, user_id, right_id}
                                res_need_check.id = 0;
                                res_need_check.data.userId = Devices[device_id].resources[i].data.userId;
                                check_policy(res_need_check, 0, user_id, 0)
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



// inline SecurityProperties(user_id){
//     atomic{
//     }

// }


proctype ProcessHost(){
    int i = 0;
    int j = 0;
    int k = 0;

    bool flag_1 = false;
    bool flag_2 = false;
    bool flag_3 = false;

    bool check_policy_result = false;
    Resource res_need_check;
    do
        :: Yunmai_smart_scale_SHARE(host, guest, Devices[0].id);
        :: Yunmai_smart_scale_REVOKE(host, guest, Devices[0].id);
        :: Operation_read_personaldata(host, Devices[0].id);
    od;
}

proctype ProcessGuest(){
    int i = 0;
    int j = 0;
    int k = 0;

    bool flag_1 = false;
    bool flag_2 = false;
    bool flag_3 = false;

    bool check_policy_result = false;
    Resource res_need_check;

    do
        :: Yunmai_smart_scale_GUESTMODE(guest, Devices[0].id, true);
        :: Operation_read_personaldata(guest, Devices[0].id);
    od;

}




init
{	
    atomic{
        /******************** Users *************************/
        Users[0] = host;
        Users[1] = guest;



        /******************** Devices *************************/
        // Yunmai smart scale
        Devices[0].id = 0;
        Devices[0].resources[0].id = 0;
        Devices[0].resources[0].data.userId = host;
        Devices[0].resources[0].data.isEmpty = false;
        Devices[0].resources[1].id = 0;
        Devices[0].resources[1].data.userId = guest;
        Devices[0].resources[1].data.isEmpty = true;
        Devices[0].resources[2].id = 1;

        // Philips hue brdige
        Devices[1].id = 1;


        /******************** Default Policies *************************/
        // Yunmai smart scale
        // DefaultPolicy	data[Client_*] [MiHome]	[Client_owner]	[View, Control(create)]
        Policies[PolicyNum].id = PolicyNum;
        Policies[PolicyNum].resource.id = 0;    
        Policies[PolicyNum].resource.data.userId = ALLUSERS;
        Policies[PolicyNum].chans[0].id = 0;
        Policies[PolicyNum].subs[0].id = host;
        Policies[PolicyNum].rights[0].id = 0;
        Policies[PolicyNum].rights[1].id = 1;
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


        // Philips hue brdige



    }
    // host: {userId = 1}
    run ProcessHost(); 
    // guest: {userId = 2}
    run ProcessGuest(); 
}