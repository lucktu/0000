#include "../src/n2n.h"
#include "n2n_win32.h"

#ifdef _WIN32

static SERVICE_STATUS_HANDLE service_status_handle;
static SERVICE_STATUS service_status;

HANDLE event_log = INVALID_HANDLE_VALUE;

static bool scm_startup_complete = false;

extern int main(int argc, char* argv[]);

int scm_start_service(uint32_t, wchar_t**);

wchar_t scm_name[_SCM_NAME_LENGTH];

int scm_startup(wchar_t* name) {
    wcsncpy(scm_name, name, _SCM_NAME_LENGTH);

    SERVICE_TABLE_ENTRYW dispatch_table[] =
    {
        { scm_name, (LPSERVICE_MAIN_FUNCTIONW) scm_start_service },
        { NULL, NULL }
    };

    if (scm_startup_complete) {
        return 0;
    }

    scm_startup_complete = true;

    if (!StartServiceCtrlDispatcherW(dispatch_table)) {
        if (GetLastError() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            /* not running as a service */
            return 0;
        } else {
            exit(1);
        }
    }

    return 1;
}

static void ReportSvcStatus(uint32_t dwCurrentState, uint32_t dwWin32ExitCode, uint32_t dwWaitHint) {
    service_status.dwCurrentState = dwCurrentState;
    service_status.dwWin32ExitCode = dwWin32ExitCode;
    service_status.dwWaitHint = dwWaitHint;

    if (dwCurrentState == SERVICE_START_PENDING)
        service_status.dwControlsAccepted = 0;
    else
        service_status.dwControlsAccepted = SERVICE_ACCEPT_STOP;

    if ((dwCurrentState == SERVICE_RUNNING) || (dwCurrentState == SERVICE_STOPPED))
        service_status.dwCheckPoint = 0;
    else
        service_status.dwCheckPoint = 1;

    SetServiceStatus(service_status_handle, &service_status);
}

static VOID WINAPI service_handler(DWORD dwControl) {
    switch (dwControl) {
    case SERVICE_CONTROL_STOP: {
        ReportSvcStatus(SERVICE_STOP_PENDING, NO_ERROR, 500);
        ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
        return;
    }
    case SERVICE_CONTROL_INTERROGATE:
        break;
    default:
        break;
    }

    ReportSvcStatus(service_status.dwCurrentState, NO_ERROR, 0);
}

#define REGKEY_TEMPLATE L"SOFTWARE\\n2n"

int get_argv_from_registry(wchar_t* scm_name, char*** argv) {
#define ARGUMENT_LENGTH 4048
    wchar_t regpath[1024];
    HKEY key;

    swprintf(regpath, sizeof(regpath), REGKEY_TEMPLATE "\\%s", scm_name);

    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, regpath, 0, KEY_READ, &key)) {
        W32_ERROR(GetLastError(), error)
        traceEvent(TRACE_ERROR, "Could not open key HKLM\\%ls: %ls", regpath, error);
        W32_ERROR_FREE(error)
        return 0;
    }

    wchar_t data[ARGUMENT_LENGTH];
    uint32_t len = ARGUMENT_LENGTH;
    uint32_t type = 0;
    if (RegGetValue(key, NULL, L"Arguments", RRF_RT_REG_SZ | RRF_RT_REG_MULTI_SZ, &type, &data, &len)) {
        W32_ERROR(GetLastError(), error)
        traceEvent(TRACE_ERROR, "Registry key HKLM\\%ls has no string value 'Arguments': %ls", regpath, error);
        W32_ERROR_FREE(error);
        return 0;
    }

    int maxargc = 16;
    int argc = 0;
    *argv = (char**) malloc(maxargc * sizeof(char*));
    size_t buffer_size = (wcslen(scm_name) + 1);
    (*argv)[argc] = malloc(buffer_size);
    wcstombs((*argv)[argc], scm_name, buffer_size);
    argc++;

    if (type == REG_SZ) {
        wchar_t* buffer = data;
        wchar_t* buff = buffer;
        while(buff) {
            wchar_t* p = wcschr(buff, L' ');
            if (p) {
                *p = L'\0';
                buffer_size = (wcslen(buff) + 1);
                (*argv)[argc] = malloc(buffer_size);
                wcstombs((*argv)[argc], buff, buffer_size);
                argc++;
                while(*++p == ' ' && *p != '\0');
                buff = p;
                if (argc >= maxargc) {
                    maxargc *= 2;
                    *argv = (char **) realloc(*argv, maxargc * sizeof(char*));
                    if (*argv == NULL) {
                        traceEvent(TRACE_ERROR, "Unable to re-allocate memory");
                        for (int i = 0; i < argc; i++) {
                            free((*argv)[i]);
                        }
                        free(*argv);
                        return 0;
                    }
                }
            } else {
                buffer_size = (wcslen(buff) + 1);
                (*argv)[argc] = malloc(buffer_size);
                wcstombs((*argv)[argc], buff, buffer_size);
                argc++;
                break;
            }
        }
    } else if (type == REG_MULTI_SZ) {
        wchar_t* buffer = data;

        while(*buffer) {
            buffer_size = (wcslen(buffer) + 1);
            (*argv)[argc] = malloc(buffer_size);
            wcstombs((*argv)[argc], buffer, buffer_size);
            argc++;
            if (argc >= maxargc) {
                maxargc *= 2;
                *argv = (char **) realloc(*argv, maxargc * sizeof(char*));
                if (*argv == NULL) {
                    traceEvent(TRACE_ERROR, "Unable to re-allocate memory");
                    for (int i = 0; i < argc; i++) {
                        free((*argv)[i]);
                    }
                    free(*argv);
                    return 0;
                }
            }
            buffer = buffer + buffer_size;
        }
    } else {
        traceEvent(TRACE_ERROR, "Registry value HKLM\\%ls\\Arguments is of unknown type %u", regpath, type);
    }

    RegCloseKey(key);

    return argc;
}

int scm_start_service(uint32_t num, wchar_t** args) {
    wcsncpy(scm_name, args[0], _SCM_NAME_LENGTH);

    service_status_handle = RegisterServiceCtrlHandlerW(scm_name, service_handler);
    event_log = RegisterEventSource(NULL, scm_name);

    ZeroMemory(&service_status, sizeof(service_status));
    service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    ReportSvcStatus(SERVICE_START_PENDING, NO_ERROR, 300);
    ReportSvcStatus(SERVICE_RUNNING, NO_ERROR, 0);

    char** argv = NULL;
    int argc = get_argv_from_registry(scm_name, &argv);

    if (!argv) {
        ReportSvcStatus(SERVICE_STOP_PENDING, ERROR_BAD_CONFIGURATION, 500);
        ReportSvcStatus(SERVICE_STOPPED, ERROR_BAD_CONFIGURATION, 0);
        return -1;
    } else {
        /*
         * note that memory allocated for argv WILL leak, but the program
         * exits directly after running main, so ...
         */
        return main(argc, argv);
    }
}

#endif /* _WIN32 */
