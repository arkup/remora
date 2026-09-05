#ifndef RESOURCE_H
#define RESOURCE_H

#define IDI_APPICON         100

#define IDM_MAINMENU        200
#define IDM_FILE_OPEN       201
#define IDM_FILE_EXIT       202
#define IDM_FILE_TERMINATE  203
#define IDM_FILE_SAVE_LOG   204
#define IDM_FILE_LAUNCH     205
#define IDM_FILE_SAVE_SUMMARY 206
#define IDM_VIEW_CLEAR      210
#define IDM_VIEW_FILTER     211
#define IDM_VIEW_MEMVIEW    212
#define IDM_VIEW_STRSCAN    213
#define IDM_VIEW_STACK      214
#define IDM_VIEW_MODULES    215
#define IDM_VIEW_DASM       216
#define IDM_VIEW_DEBUGLOG   220
#define IDM_HELP_ABOUT      221

#define IDD_ABOUT           1090
#define IDC_ABOUT_LINK      1091
#define IDC_ABOUT_BUILD     1092
#define IDC_ABOUT_LOGO      1093
#define IDB_LOGO            101
#define IDM_CFG_FONT        229
#define IDM_CFG_DASM_DBLCLK 230
#define IDM_CFG_AUTODUMP    231
#define IDM_CFG_AUTOSCROLL  232
#define IDM_CFG_BUFCAPTURE  233
#define IDM_CFG_COALESCE    234
#define IDM_CFG_SAVEPOS     235
#define IDM_CFG_BREAK_OEP   236
#define IDM_CFG_SAVESETTINGS 237
#define IDM_CFG_SILENCE_BORING 238
#define IDM_JAIL_BASE       300
#define IDM_JAIL_COND_BASE  600

#define IDD_CONDITION       1070
#define IDC_COND_EDIT       1071
#define IDC_COND_CLEAR      1072
#define IDC_COND_HINT       1073

#define IDC_RICHEDIT        1000
#define IDC_STATUS          1002
#define IDC_ASK_BAR         1004
#define IDC_ASK_LABEL       1005
#define IDC_BTN_ALLOW       1006
#define IDC_BTN_BLOCK       1007
#define IDC_BTN_ALLOW_ALL   1008
#define IDC_BTN_STACK       1009
#define IDC_FIND_BAR        1010
#define IDC_FIND_EDIT       1011
#define IDC_BTN_FIND_NEXT   1012
#define IDC_BTN_FIND_PREV   1013
#define IDC_BTN_FIND_CLOSE  1014
#define IDC_TOOLBAR         1015

#define IDM_FIND            1020
#define IDM_FIND_NEXT       1021
#define IDM_FIND_PREV       1022
#define IDM_FIND_CLOSE      1023
#define IDM_TB_START        1030
#define IDM_TB_FILT_BASE    1031
#define IDM_TB_FILT_FILE    1031
#define IDM_TB_FILT_PROCESS 1032
#define IDM_TB_FILT_MEMORY  1033
#define IDM_TB_FILT_REGISTRY 1034
#define IDM_TB_FILT_NETWORK 1035
#define IDM_TB_FILT_HTTP    1036
#define IDM_TB_FILT_MODULE  1037
#define IDM_TB_FILT_CRYPTO  1038
#define IDM_TB_FILT_GENERAL 1039

#define IDM_FILT_FILE       1080
#define IDM_FILT_PROCESS    1081
#define IDM_FILT_MEMORY     1082
#define IDM_FILT_REGISTRY   1083
#define IDM_FILT_NETWORK    1084
#define IDM_FILT_HTTP       1085
#define IDM_FILT_MODULE     1086
#define IDM_FILT_CRYPTO     1087
#define IDM_FILT_GENERAL    1088

#define FILT_COUNT          9
#define FILT_GENERAL_IDX    8

#define IDM_VIEW_SANDBOX_RPT 217
#define IDM_EDIT_SUSPEND     218
#define IDM_JAIL_POLICIES   281

#define IDD_OFN_ARGS        1040
#define IDC_OT_ARGS_LABEL   1041
#define IDC_OT_ARGS_EDIT    1042

#define IDM_JAIL_RULES      280

#define IDD_JAIL_RULES      1050
#define IDC_RULES_LIST      1051
#define IDC_RULES_ADD       1052
#define IDC_RULES_EDIT      1053
#define IDC_RULES_DEL       1054
#define IDC_RULES_UP        1055
#define IDC_RULES_DOWN      1056

#define IDD_RULE_EDIT       1060
#define IDC_RE_HOOK         1061
#define IDC_RE_STR_TYPE     1062
#define IDC_RE_STR_PAT      1063
#define IDC_RE_NUM_TYPE     1064
#define IDC_RE_NUM_VAL      1065
#define IDC_RE_ACTION       1066
#define IDC_RE_ENABLED      1067

#define IDT_EP_SUSPEND      2000
#define IDT_LOG_FLUSH       2001
#define IDT_COALESCE_FLUSH  2002
#define WM_IPC_MSG          (WM_USER + 1)
#define WM_LAUNCH_DONE      (WM_USER + 2)
#define WM_TARGET_EXIT      (WM_USER + 3)

#endif
