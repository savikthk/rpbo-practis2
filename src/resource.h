#pragma once

// Icon
#define IDI_APPICON      101

// Menus
#define IDR_MAINMENU     102

// Menu commands
#define ID_FILE_EXIT     40001
#define ID_TRAY_OPEN     40002
#define ID_TRAY_EXIT     40003
#define ID_FILE_LOGOUT   40004

// Child control IDs (login pane)
#define IDC_LOGIN_EMAIL    50001
#define IDC_LOGIN_PASS     50002
#define IDC_LOGIN_BUTTON   50003
#define IDC_LOGIN_STATUS   50004

// Child control IDs (main / activation pane)
#define IDC_USER_LABEL     50101
#define IDC_LIC_LABEL      50102
#define IDC_ACT_KEY        50103
#define IDC_ACT_BUTTON     50104
#define IDC_ACT_STATUS     50105
#define IDC_AV_BUTTON      50106
#define IDC_LOGOUT_BUTTON  50107

// Child control IDs (AV scanning — licensed pane)
#define IDC_AV_DB_LABEL        50108
#define IDC_SCAN_FILE_BTN      50109
#define IDC_SCAN_DIR_BTN       50110
#define IDC_SCAN_ALL_DRIVES    50111
#define IDC_SCHED_PATH_EDIT    50112
#define IDC_SCHED_INTV_EDIT    50113
#define IDC_SCHED_SET_BTN      50114
#define IDC_SCHED_CLEAR_BTN    50115
#define IDC_SCHED_RESULTS_BTN  50116
#define IDC_MON_PATH_EDIT      50117
#define IDC_MON_ADD_BTN        50118
#define IDC_MON_REMOVE_BTN     50119
#define IDC_MON_RESULTS_BTN    50120

// Custom window messages
#define WM_TRAYICON      (WM_USER + 1)
#define IDT_POLL_TIMER   1
