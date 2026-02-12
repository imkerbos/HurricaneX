#ifndef HURRICANE_CONFIG_H
#define HURRICANE_CONFIG_H

#include "common.h"

/* Engine configuration loaded from YAML via control plane */
typedef struct hx_config {
    /* Target */
    char     target_host[256];
    hx_u16   target_port;
    bool     use_tls;

    /* Engine tuning */
    hx_u32   num_workers;
    hx_u32   connections;
    hx_u32   cps;            /* connections per second target */
    hx_u32   duration_sec;

    /* Network */
    char     local_ip[64];
    char     gateway_mac[18];

    /* Memory */
    hx_u32   mempool_size;   /* number of mbufs */
} hx_config_t;

/* Initialize config with defaults */
hx_result_t hx_config_init(hx_config_t *cfg);

#endif /* HURRICANE_CONFIG_H */
