#include "hurricane/config.h"
#include <string.h>

hx_result_t hx_config_init(hx_config_t *cfg)
{
    if (!cfg)
        return HX_ERR_INVAL;

    memset(cfg, 0, sizeof(*cfg));

    /* Defaults */
    cfg->target_port = 80;
    cfg->use_tls = false;
    cfg->num_workers = 1;
    cfg->connections = 1000;
    cfg->cps = 100;
    cfg->duration_sec = 10;
    cfg->mempool_size = 65536;

    return HX_OK;
}
