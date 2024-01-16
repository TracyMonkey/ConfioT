#define MAXUSER 2
#define MAXCHANNEL 2
#define MAXSUBJECT 2
#define MAXRIGHT 5
#define MAXRESOURCE 20
#define MAXPOLICY 50

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
typedef IoTDevice{
    short id = -1;
    short canBeRevokedNum = 0;
    PolicyBeRevoked canBeRevoked[MAXPOLICY];
    Resource resources[MAXRESOURCE];
}

short Users[MAXUSER];
// ALL resources
IoTDevice Device;
// Policies will be traversed from the last one (latest) to the first one
Policy Policies[MAXPOLICY];

short PolicyNum = 0;
short Shared = 0;


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




/******************** Configurations *************************/
{%- for config in Configurations %}
inline {{config.ConfigName}}(
{%- for param in config.Params -%}
{%- if loop.index0 != 0 -%}
,
{%- endif -%}
{{param}}
{%- endfor -%}
)
{
    atomic{
        check_policy_result = false;
        {%- for constrain in config.Constrains %}
            res_need_check.id = {{constrain.resource.id}};
            {% if constrain.resource.id == 0 -%}
                res_need_check.data.userId = {{constrain.resource.user}};
            {% elif constrain.resource.id == 3 -%}
                res_need_check.history.userId = {{constrain.resource.user}}
            {% endif -%}
            check_policy(res_need_check, {{constrain.channel}}, {{constrain.user}}, {{constrain.rights[0]}});
        {% endfor %}


        if
            ::  (check_policy_result == true) ->
                printf("user_%d perform {{config.ConfigName}} \n", {{config.Params[0]}});



                {%- for dp in config.Policies %}
                // Create Policies
                    {% if dp.canBeRevoked == 1 -%}
                        Device.canBeRevoked[Device.canBeRevokedNum].id = PolicyNum;
                        Device.canBeRevokedNum = Device.canBeRevokedNum + 1;
                    {% endif -%}
                    Policies[PolicyNum].id = PolicyNum;
                    Policies[PolicyNum].resource.id = {{dp.resource.id}};
                    {% if dp.resource.id == 0 -%}
                        Policies[PolicyNum].resource.data.userId = {{dp.resource.user}};
                    {% elif dp.resource.id == 3 -%}
                        Policies[PolicyNum].resource.history.userId = {{dp.resource.user}};
                    {% endif -%}
                        Policies[PolicyNum].chans[0].id = {{dp.channel}};
                        Policies[PolicyNum].subs[0].id = {{dp.user}};
                    {% for r in dp.rights -%}
                        Policies[PolicyNum].rights[{{loop.index0}}].id = {{r}};
                    {% endfor -%}
                        PolicyNum = PolicyNum + 1;
                {% endfor %}


                {% if config.isREVOKE == 1 -%}
                    i = 0;
                    do
                        :: (i < MAXPOLICY) ->
                            if
                                :: (Device.canBeRevoked[i].id == -1) -> break;
                                :: else ->
                                    Policies[Device.canBeRevoked[i].id].banned = true;
                            fi;
                            i = i + 1;
                        :: else -> break;
                    od;
                    Operation_After_Revoke({{config.Params[1]}})

                    shared = 0;
                {% endif -%}

                {% if config.isSHARE == 1 -%}
                    Shared = 1;
                {% endif -%}

            :: else ->
                skip;
        fi;
    }
}
{% endfor %}



/******************** OPERATIONS *************************/

inline Operation_read_personaldata(userA){
    atomic{
        i = 0;
        do
            :: (i < MAXRESOURCE) ->
                if
                    :: (Device.resources[i].id == -1) -> break;
                    :: (Device.resources[i].id == 0) ->
                        if
                            :: (Device.resources[i].data.isEmpty == false) ->

                                check_policy_result = false;
                                // {resource:0, channel_id:-1, userA, right_id}
                                res_need_check.id = 0;
                                res_need_check.data.userId = Device.resources[i].data.userId;
                                check_policy(res_need_check, -1, userA, 0)
                                if
                                    ::  (check_policy_result == true) ->
                                    printf("user_%d read personal data of user_%d through 'MiHome app'\n", userA, Device.resources[i].data.userId);

                                        assert (userA == Device.resources[i].data.userId);
                                    :: else ->
                                        skip;
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

inline Operation_read_accesslist(userA){
    atomic{
        check_policy_result = false;
        // {resource:1, channel_id:*, userA, right_id}
        res_need_check.id = 1;
        check_policy(res_need_check, -1, userA, 0)
        if
            ::  (check_policy_result == true) ->
                skip;

            :: else ->
                printf("user_%d failed to read accesslist\n", userA);
                assert (1 == 2);

        fi;

    }
}


inline Operation_control_subdevicelist(userA){
    atomic{

        check_policy_result = false;
        // {resource:4, channel_id: mihome, userA:, right_id: remove}
        res_need_check.id = 4;
        check_policy(res_need_check, 0, userA, 2)
        if
            ::  (check_policy_result == true) ->
            printf("user_%d control SubDeviceList\n", userA);

                assert(userA == host);

            :: else ->
                skip;
        fi;

    }
}

// Property: user_B should not be able to control the device after revocation
inline Operation_After_Revoke(userA){
    atomic{

        check_policy_result = false;
        // {resource:state, channel_id: *, userA:, right_id: view}
        res_need_check.id = 5;
        check_policy(res_need_check, -1, userA, 0)
        if
            ::  (check_policy_result == true) ->
                printf("After Revocation\n");

                assert(userA == host);

            :: else ->
                skip;
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


    bool COMPETE_host_1 = false;
    bool COMPETE_host_2 = false;
    bool COMPETE_host_3 = false;



    {%- for config in Configurations %}
        bool COMPETE_host_{{config.ConfigName}} = false;
    {% endfor %}

    do
        ::
            atomic{
                if
                    :: (COMPETE_host_1 == false) ->
                        COMPETE_host_1 = true;
                        Operation_control_subdevicelist(host);
                fi;
            }
        ::
            atomic{
                if
                    :: (COMPETE_host_2 == false) ->
                        COMPETE_host_2 = true;
                        Operation_read_accesslist(host);
                fi;
            }
        ::
            atomic{
                if
                    :: (COMPETE_host_3 == false) ->
                        COMPETE_host_3 = true;
                        Operation_read_personaldata(host);
                fi;
            }

    {%- for config in Configurations %}
        ::
            atomic{
                if
                    :: (COMPETE_host_{{config.ConfigName}} == false) ->
                        COMPETE_host_{{config.ConfigName}} = true;
                        {% if config.ParamsLen == 1 -%}
                            {{config.ConfigName}}(host);
                        {% else -%}
                            {{config.ConfigName}}(host, guest);
                        {% endif %}
                fi;
            }
    {% endfor %}

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


    bool COMPETE_guest_1 = false;
    bool COMPETE_guest_2 = false;
    bool COMPETE_guest_3 = false;



    {%- for config in Configurations %}
        bool COMPETE_guest_{{config.ConfigName}} = false;
    {% endfor %}

    do
        ::
            atomic{
                if
                    :: (COMPETE_guest_1 == false) ->
                        COMPETE_guest_1 = true;
                        Operation_control_subdevicelist(guest);
                fi;
            }
        ::
            atomic{
                if
                    :: (COMPETE_guest_2 == false && Shared == 1) ->
                        COMPETE_guest_2 = true;
                        Operation_read_accesslist(guest);
                fi;
            }
        ::
            atomic{
                if
                    :: (COMPETE_guest_3 == false) ->
                        COMPETE_guest_3 = true;
                        Operation_read_personaldata(guest);
                fi;
            }

    {%- for config in Configurations %}
    {% if config.ParamsLen == 1 -%}
        ::
            atomic{
                if
                    :: (COMPETE_guest_{{config.ConfigName}} == false) ->
                        COMPETE_guest_{{config.ConfigName}} = true;
                        {% if config.ParamsLen == 1 -%}
                            {{config.ConfigName}}(guest);
                        {% else -%}
                            {{config.ConfigName}}(guest, host);
                        {% endif %}
                fi;
            }
    {% endif %}
    {% endfor %}

    od;
}



init
{
    atomic{

        /******************** Users *************************/
        Users[0] = host;
        Users[1] = guest;


        /******************** Device *************************/
            Device.id = 0;
        {% for res in Resources -%}
            Device.resources[{{ loop.index0 }}].id = {{ res.id }};
            {% if res.id == 0 -%}
            Device.resources[{{ loop.index0 }}].data.userId = {{res.user}};
            Device.resources[{{ loop.index0 }}].data.isEmpty = true;
            {% elif res.id == 3 -%}
            Device.resources[{{ loop.index0 }}].history.userId = {{res.user}};
            Device.resources[{{ loop.index0 }}].history.isEmpty = true;
            {% endif -%}
        {% endfor %}

        /******************** Default Policies *************************/

        {%- for dp in DefaultPolicies %}
            {% if dp.canBeRevoked == 1 -%}
                Device.canBeRevoked[Device.canBeRevokedNum].id = PolicyNum;
                Device.canBeRevokedNum = Device.canBeRevokedNum + 1;
            {% endif -%}
            Policies[PolicyNum].id = PolicyNum;
            Policies[PolicyNum].resource.id = {{dp.resource.id}};
            {% if dp.resource.id == 0 -%}
                Policies[PolicyNum].resource.data.userId = {{dp.resource.user}};
            {% elif dp.resource.id == 3 -%}
                Policies[PolicyNum].resource.history.userId = {{dp.resource.user}};
            {% endif -%}
                Policies[PolicyNum].chans[0].id = {{dp.channel}};
                Policies[PolicyNum].subs[0].id = {{dp.user}};
            {% for r in dp.rights -%}
                Policies[PolicyNum].rights[{{loop.index0}}].id = {{r}};
            {% endfor -%}
                PolicyNum = PolicyNum + 1;
        {% endfor %}


    }


    // host: {userId = 1}
    run ProcessHost();
    // guest: {userId = 2}
    run ProcessGuest();
}
