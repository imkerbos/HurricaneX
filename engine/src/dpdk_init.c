#ifdef HX_USE_DPDK

#include "hurricane/dpdk.h"
#include "hurricane/log.h"

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <pthread.h>

#define HX_LOG_COMP_DPDK "dpdk"

static pthread_once_t s_eal_once = PTHREAD_ONCE_INIT;
static bool           s_eal_initialized = false;
static hx_result_t    s_eal_result = HX_ERR_DPDK;

/* Stored config pointer for the pthread_once callback */
static const hx_dpdk_config_t *s_init_cfg = NULL;

static void eal_init_once(void)
{
    if (!s_init_cfg) {
        HX_LOG_ERROR(HX_LOG_COMP_DPDK, "EAL init called with NULL config");
        s_eal_result = HX_ERR_INVAL;
        return;
    }

    int ret = rte_eal_init(s_init_cfg->argc, s_init_cfg->argv);
    if (ret < 0) {
        HX_LOG_ERROR(HX_LOG_COMP_DPDK, "rte_eal_init failed: ret=%d", ret);
        s_eal_result = HX_ERR_DPDK;
        return;
    }

    uint16_t nb_ports = rte_eth_dev_count_avail();
    HX_LOG_INFO(HX_LOG_COMP_DPDK, "EAL initialized, available ports: %u",
                (unsigned)nb_ports);

    s_eal_initialized = true;
    s_eal_result = HX_OK;
}

hx_result_t hx_dpdk_init(const hx_dpdk_config_t *cfg)
{
    if (!cfg)
        return HX_ERR_INVAL;

    s_init_cfg = cfg;
    pthread_once(&s_eal_once, eal_init_once);
    return s_eal_result;
}

bool hx_dpdk_is_initialized(void)
{
    return s_eal_initialized;
}

void hx_dpdk_cleanup(void)
{
    if (s_eal_initialized) {
        rte_eal_cleanup();
        s_eal_initialized = false;
        HX_LOG_INFO(HX_LOG_COMP_DPDK, "EAL cleaned up");
    }
}

#endif /* HX_USE_DPDK */
