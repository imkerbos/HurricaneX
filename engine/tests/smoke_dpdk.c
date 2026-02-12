/*
 * DPDK pktio backend smoke test.
 *
 * Verifies: EAL init → port open → RX burst (expect 0 pkts) → close → cleanup.
 * Requires: root, hugepages, NIC bound to vfio-pci.
 *
 * Usage:
 *   ./smoke_dpdk --lcores 0 -a <PCI_ADDR>
 *   e.g. ./smoke_dpdk --lcores 0 -a 7f:00.0
 */
#ifdef HX_USE_DPDK

#include "hurricane/dpdk.h"
#include "hurricane/pktio.h"
#include "hurricane/mempool.h"
#include "hurricane/log.h"

#include <stdio.h>
#include <stdlib.h>

#define LOG_COMP "smoke"

int main(int argc, char **argv)
{
    printf("=== HurricaneX DPDK smoke test ===\n");

    /* 1. EAL init */
    hx_dpdk_config_t cfg = { .argc = argc, .argv = argv };
    hx_result_t rc = hx_dpdk_init(&cfg);
    if (rc != HX_OK) {
        fprintf(stderr, "FAIL: hx_dpdk_init: %s\n", hx_strerror(rc));
        return 1;
    }
    printf("PASS: EAL initialized\n");

    /* 2. mempool (needed by pktio_init, DPDK backend ignores it) */
    hx_mempool_t *mp = hx_mempool_create("smoke", 64, 2048);
    if (!mp) {
        fprintf(stderr, "FAIL: hx_mempool_create\n");
        return 1;
    }

    /* 3. Open DPDK port 0 */
    hx_pktio_t io;
    rc = hx_pktio_init(&io, &hx_pktio_dpdk_ops, "dpdk:0", mp);
    if (rc != HX_OK) {
        fprintf(stderr, "FAIL: hx_pktio_init(dpdk:0): %s\n", hx_strerror(rc));
        hx_mempool_destroy(mp);
        return 1;
    }
    printf("PASS: port 0 opened\n");

    /* 4. Try RX burst (expect 0 packets, just verify no crash) */
    hx_pkt_t *pkts[HX_MAX_BURST];
    int nb_rx = hx_pktio_rx_burst(&io, pkts, HX_MAX_BURST);
    printf("PASS: rx_burst returned %d packets\n", nb_rx);

    /* Free any received packets */
    for (int i = 0; i < nb_rx; i++)
        hx_pktio_free_pkt(&io, pkts[i]);

    /* 5. Cleanup */
    hx_pktio_close(&io);
    printf("PASS: port closed\n");

    hx_mempool_destroy(mp);
    hx_dpdk_cleanup();
    printf("PASS: EAL cleaned up\n");

    printf("=== ALL PASSED ===\n");
    return 0;
}

#else /* !HX_USE_DPDK */

#include <stdio.h>

int main(void)
{
    fprintf(stderr, "This test requires HX_USE_DPDK. "
                    "Build with DPDK to run.\n");
    return 77; /* skip */
}

#endif
