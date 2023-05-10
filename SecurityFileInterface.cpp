#include <iostream>
#include <tss2/tss2_sys.h>
#include <tss2/tss2_tcti.h>
#include <tss2/tss2_tctildr.h>

int main()
{
    TSS2_RC rc;
    TSS2_SYS_CONTEXT *sapi_context;
    TSS2_TCTI_CONTEXT *tcti_context;

    // Initialize the default TCTI context
    rc = Tss2_TctiLdr_Initialize(NULL, &tcti_context);
    if (rc != TSS2_RC_SUCCESS) {
        std::cerr << "Error: Tss2_TctiLdr_Initialize returned " << rc << std::endl;
        return 1;
    }

    // Initialize the SAPI context
    size_t context_size = Tss2_Sys_GetContextSize(0);
    sapi_context = (TSS2_SYS_CONTEXT*) malloc(context_size);
    rc = Tss2_Sys_Initialize(sapi_context, context_size, tcti_context, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        std::cerr << "Error: Tss2_Sys_Initialize returned " << rc << std::endl;
        return 1;
    }

    TPMI_YES_NO more_data = TPM2_NO;
    TPMS_CAPABILITY_DATA capability;
    TSS2L_SYS_AUTH_COMMAND auth_cmd = {0};
    TSS2L_SYS_AUTH_RESPONSE auth_resp = {0};
    rc = Tss2_Sys_GetCapability(sapi_context, &auth_cmd, TPM2_CAP_TPM_PROPERTIES, TPM2_PT_NV_COUNTERS_MAX, 1, &more_data, &capability, &auth_resp);
    if (rc != TSS2_RC_SUCCESS) {
        std::cerr << "Error: Tss2_Sys_GetCapability returned " << rc << std::endl;
    } else {
        UINT32 max_nv_counters = capability.data.tpmProperties.tpmProperty[0].value;
        std::cout << "Maximum number of NV counters: " << max_nv_counters << std::endl;
    }

    Tss2_Sys_Finalize(sapi_context);
    Tss2_TctiLdr_Finalize(&tcti_context);

    return 0;
}
