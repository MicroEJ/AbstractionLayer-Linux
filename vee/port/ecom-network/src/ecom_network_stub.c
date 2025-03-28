/*
 * C
 *
 * Copyright 2024 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "ecom_network_helper.h"
#include "microej_async_worker.h"
#include "LLECOM_NETWORK_impl.h"

#define DNS_MAX_SERVERS (1)

#ifdef __cplusplus
extern "C" {
#endif

/* global to know if configuration is static or dhcp */
static int8_t ecom_network_is_static;

void LLECOM_NETWORK_IMPL_enable_action(MICROEJ_ASYNC_WORKER_job_t* job) {

	ECOM_NETWORK_netif_context_t* param = (ECOM_NETWORK_netif_context_t*) job->params;

	if (param->netifName == NULL) {
		param->result = -1;
		if (param->error_message != NULL) {
			param->error_message = "null pointer";
		}
	} else {
#ifdef LWIP
		struct netif* interface;

		interface = netif_find((char *)param->netifName);

		if (interface != NULL) {
			netif_set_up(interface);
			param->result = 0;
		} else {
			param->result = -1;
			if (param->error_message != NULL) {
				param->error_message = "interface not found";
			}
		}
#endif // LWIP
	}

	LLECOM_NETWORK_DEBUG_TRACE("[%s:%u] interface enabled with result : %d (err %d)\n", __func__, __LINE__, param->result, param->error_code);
}

void LLECOM_NETWORK_IMPL_disable_action(MICROEJ_ASYNC_WORKER_job_t* job) {

	ECOM_NETWORK_netif_context_t* param = (ECOM_NETWORK_netif_context_t*) job->params;

	if (param->netifName == NULL) {
		param->result = -1;
		if (param->error_message != NULL) {
			param->error_message = "null pointer";
		}
	} else {
#ifdef LWIP
		struct netif* interface;

		interface = netif_find((char *)param->netifName);

		if (interface != NULL) {
			netif_set_down(interface);
			param->result = 0;
		} else {
			param->result = -1;
			if (param->error_message != NULL) {
				param->error_message = "interface not found";
			}
		}
#endif // LWIP
	}

	LLECOM_NETWORK_DEBUG_TRACE("[%s:%u] interface disabled with result : %d (err %d)\n", __func__, __LINE__, param->result, param->error_code);
}

void LLECOM_NETWORK_IMPL_isEnabled_action(MICROEJ_ASYNC_WORKER_job_t* job) {

	ECOM_NETWORK_netif_context_t* param = (ECOM_NETWORK_netif_context_t*) job->params;

	if (param->netifName == NULL) {
		param->result = -1;
		if (param->error_message != NULL) {
			param->error_message = "null pointer";
		}
	} else {
#ifdef LWIP
		struct netif* interface;

		interface = netif_find((char *)param->netifName);

		if (interface != NULL) {
			param->result = netif_is_up(interface) ? IF_STATE_ENABLED : IF_STATE_NOT_ENABLED;
		} else {
			param->result = -1;
			if (param->error_message != NULL) {
				param->error_message = "interface not found";
			}
		}
#endif // LWIP
	}

	LLECOM_NETWORK_DEBUG_TRACE("[%s:%u] result : %d (err %d)\n", __func__, __LINE__, param->result, param->error_code);
}

void LLECOM_NETWORK_IMPL_start_action(MICROEJ_ASYNC_WORKER_job_t* job) {

	ECOM_NETWORK_netif_context_t* param = (ECOM_NETWORK_netif_context_t*) job->params;

	if (param->netifName == NULL) {
		param->result = -1;
		if (param->error_message != NULL) {
			param->error_message = "null pointer";
		}
	} else {
		if (LLECOM_NETWORK_IMPL_start(param->netifName, param->netifNameOffset, param->netifNameLength, param->getResult)) {
			param->result = 0;
		} else {
			param->result = -1;
			if (param->error_message != NULL) {
				param->error_message = "Network driver error";
			}
		}
	}

	LLECOM_NETWORK_DEBUG_TRACE("[%s:%u] interface started with result : %d (err %d)\n", __func__, __LINE__, param->result, param->error_code);
}

void LLECOM_NETWORK_IMPL_stop_action(MICROEJ_ASYNC_WORKER_job_t* job) {

	ECOM_NETWORK_netif_context_t* param = (ECOM_NETWORK_netif_context_t*) job->params;

	if (param->netifName == NULL) {
		param->result = -1;
		if (param->error_message != NULL) {
			param->error_message = "null pointer";
		}
	} else {
		if (LLECOM_NETWORK_IMPL_stop(param->netifName, param->netifNameOffset, param->netifNameLength, param->getResult)) {
			param->result = 0;
		} else {
			param->result = -1;
			if (param->error_message != NULL) {
				param->error_message = "Network driver error";
			}
		}
	}

	LLECOM_NETWORK_DEBUG_TRACE("[%s:%u] interface stopped with result : %d (err %d)\n", __func__, __LINE__, param->result, param->error_code);
}

void LLECOM_NETWORK_IMPL_isStarted_action(MICROEJ_ASYNC_WORKER_job_t* job) {

	ECOM_NETWORK_netif_context_t* param = (ECOM_NETWORK_netif_context_t*) job->params;

	if (param->netifName == NULL) {
		param->result = -1;
		if (param->error_message != NULL) {
			param->error_message = "null pointer";
		}
	} else {
#ifdef LWIP

		struct netif *pnetif = netif_find((char *)param->netifName);
		if(pnetif != NULL){
			if (LLECOM_NETWORK_interface_is_started(pnetif))
				param->result = IF_STATE_STARTED;
			else
				param->result = IF_STATE_NOT_STARTED;
		} else {
			param->result = IF_STATE_NOT_STARTED;
			
		}
#endif // LWIP
	}

	LLECOM_NETWORK_DEBUG_TRACE("[%s:%u] result : %d (err %d)\n", __func__, __LINE__, param->result, param->error_code);
}

void LLECOM_NETWORK_IMPL_getDNSCount_action(MICROEJ_ASYNC_WORKER_job_t* job) {

	ECOM_NETWORK_netif_context_t* param = (ECOM_NETWORK_netif_context_t*) job->params;

	if (param->netifName == NULL) {
		param->result = -1;
		if (param->error_message != NULL) {
			param->error_message = "null pointer";
		}
	} else {
		int32_t count = 0;

#ifdef LWIP
		for (int32_t i = 0; i < DNS_MAX_SERVERS; i++) {
			const ip_addr_t* dns_addr = dns_getserver(i);

			// check if the DNS server IP address is right
			if (!ip_addr_isany(dns_addr)) {
				count++;
			} else {
				break;
			}
		}
#endif // LWIP

		param->result = count;
	}

	LLECOM_NETWORK_DEBUG_TRACE("[%s:%u] DNS counted : %d (err %d)\n", __func__, __LINE__, param->result, param->error_code);
}

void LLECOM_NETWORK_IMPL_getDNS_action(MICROEJ_ASYNC_WORKER_job_t* job) {

	ECOM_NETWORK_dns_context_t* param = (ECOM_NETWORK_dns_context_t*) job->params;

	if ((param->netifName == NULL) || (param->address == NULL) || (param->index < 0) || (param->index >= DNS_MAX_SERVERS)) {
		param->result = -1;
		if (param->error_message != NULL) {
			param->error_message = "null pointer or wrong index";
		}
	} else {
#ifdef LWIP
		const ip_addr_t* dns_addr = dns_getserver(param->index);

		// check if the DNS server IP address is right
		if (!ip_addr_isany(dns_addr)) {
			memcpy(param->address, ip_2_ip4(dns_addr), sizeof(ip4_addr_t));
			param->result = 0;
		} else {
			param->result = -1;
			if (param->error_message != NULL) {
				param->error_message = "DNS server IP address is not valid";
			}
		}
#endif // LWIP
	}

	LLECOM_NETWORK_DEBUG_TRACE("[%s:%u] get DNS result : %d (err %d)\n", __func__, __LINE__, param->result, param->error_code);
}

void LLECOM_NETWORK_IMPL_getGateway_action(MICROEJ_ASYNC_WORKER_job_t* job) {

	ECOM_NETWORK_ip_context_t* param = (ECOM_NETWORK_ip_context_t*) job->params;

	if ((param->netifName == NULL) || (param->address == NULL)) {
		param->result = -1;
		if (param->error_message != NULL) {
			param->error_message = "null pointer";
		}
	} else {
#ifdef LWIP
		struct netif* interface;

		interface = netif_find((char *)param->netifName);

		if (interface != NULL) {
			ip4_addr_set_u32((ip4_addr_t*)(param->address), *(u32_t*)netif_ip4_gw(interface));
			param->result = 0;
		} else {
			param->result = -1;
			if (param->error_message != NULL) {
				param->error_message = "interface not found";
			}
		}
#endif // LWIP
	}

	LLECOM_NETWORK_DEBUG_TRACE("[%s:%u] get gateway result : %d (err %d)\n", __func__, __LINE__, param->result, param->error_code);
}

void LLECOM_NETWORK_IMPL_getNetmask_action(MICROEJ_ASYNC_WORKER_job_t* job) {

	ECOM_NETWORK_ip_context_t* param = (ECOM_NETWORK_ip_context_t*) job->params;

	if ((param->netifName == NULL) || (param->address == NULL)) {
		param->result = -1;
		if (param->error_message != NULL) {
			param->error_message = "null pointer";
		}
	} else {
#ifdef LWIP
		struct netif* interface;

		interface = netif_find((char *)param->netifName);

		if (interface != NULL) {
			ip4_addr_set_u32((ip4_addr_t*)(param->address), *(u32_t*)netif_ip4_netmask(interface));
			param->result = 0;
		} else {
			param->result = -1;
			if (param->error_message != NULL) {
				param->error_message = "interface not found";
			}
		}
#endif // LWIP
	}

	LLECOM_NETWORK_DEBUG_TRACE("[%s:%u] get netmask result : %d (err %d)\n", __func__, __LINE__, param->result, param->error_code);
}

void LLECOM_NETWORK_IMPL_getIP_action(MICROEJ_ASYNC_WORKER_job_t* job) {

	ECOM_NETWORK_ip_context_t* param = (ECOM_NETWORK_ip_context_t*) job->params;

	if ((param->netifName == NULL) || (param->address == NULL)) {
		param->result = -1;
		if (param->error_message != NULL) {
			param->error_message = "null pointer";
		}
	} else {
#ifdef LWIP
		struct netif* interface;

		interface = netif_find((char *)param->netifName);

		if (interface != NULL) {
			ip4_addr_set_u32((ip4_addr_t*)(param->address), *(u32_t*)netif_ip4_addr(interface));
			param->result = 0;
		} else {
			param->result = -1;
			if (param->error_message != NULL) {
				param->error_message = "interface not found";
			}
		}
#endif // LWIP
	}

	LLECOM_NETWORK_DEBUG_TRACE("[%s:%u] get ip address result : %d (err %d)\n", __func__, __LINE__, param->result, param->error_code);
}

void LLECOM_NETWORK_IMPL_isDNSStatic_action(MICROEJ_ASYNC_WORKER_job_t* job) {

	ECOM_NETWORK_netif_context_t* param = (ECOM_NETWORK_netif_context_t*) job->params;

	if (param->netifName == NULL) {
		param->result = -1;
		if (param->error_message != NULL) {
			param->error_message = "null pointer";
		}
	} else {
		param->result = (ecom_network_is_static == 0) ? IF_DNS_NOT_STATIC : IF_DNS_STATIC;
	}

	LLECOM_NETWORK_DEBUG_TRACE("[%s:%u] is static DNS result : %d (err %d)\n", __func__, __LINE__, param->result, param->error_code);
}

void LLECOM_NETWORK_IMPL_isStatic_action(MICROEJ_ASYNC_WORKER_job_t* job) {

	ECOM_NETWORK_netif_context_t* param = (ECOM_NETWORK_netif_context_t*) job->params;

	if (param->netifName == NULL) {
		param->result = -1;
		if (param->error_message != NULL) {
			param->error_message = "null pointer";
		}
	} else {
		param->result = (ecom_network_is_static == 0) ? IF_IP_DYNAMIC : IF_IP_STATIC;
	}

	LLECOM_NETWORK_DEBUG_TRACE("[%s:%u] is static IP result : %d (err %d)\n", __func__, __LINE__, param->result, param->error_code);
}

void LLECOM_NETWORK_IMPL_startConfiguration_action(MICROEJ_ASYNC_WORKER_job_t* job) {

	ECOM_NETWORK_netif_context_t* param = (ECOM_NETWORK_netif_context_t*) job->params;

	if (param->netifName == NULL) {
		param->result = -1;
		if (param->error_message != NULL) {
			param->error_message = "null pointer";
		}
	} else {
		param->result = 0;
	}

	LLECOM_NETWORK_DEBUG_TRACE("[%s:%u] configuration started with result : %d (err %d)\n", __func__, __LINE__, param->result, param->error_code);
}

void LLECOM_NETWORK_IMPL_endConfiguration_action(MICROEJ_ASYNC_WORKER_job_t* job) {

	ECOM_NETWORK_netif_context_t* param = (ECOM_NETWORK_netif_context_t*) job->params;

	if (param->netifName == NULL) {
		param->result = -1;
		if (param->error_message != NULL) {
			param->error_message = "null pointer";
		}
	} else {
#ifdef LWIP
		struct netif* interface;

		interface = netif_find((char *)param->netifName);

		if (interface != NULL) {
			if (LLECOM_NETWORK_apply_configuration(interface, ecom_network_is_static, *netif_ip4_addr(interface), *netif_ip4_netmask(interface), *netif_ip4_gw(interface))) {
				param->result = 0;
			} else {
				param->result = -1;
				if (param->error_message != NULL) {
					param->error_message = "Network driver error";
				}
			}
		} else {
			param->result = -1;
			if (param->error_message != NULL) {
				param->error_message = "interface not found";
			}
		}
#endif // LWIP
	}

	LLECOM_NETWORK_DEBUG_TRACE("[%s:%u] configuration ended with result : %d (err %d)\n", __func__, __LINE__, param->result, param->error_code);
}

void LLECOM_NETWORK_IMPL_setDNS_action(MICROEJ_ASYNC_WORKER_job_t* job) {

	ECOM_NETWORK_dns_context_t* param = (ECOM_NETWORK_dns_context_t*) job->params;

	if ((param->netifName == NULL) || (param->address == NULL) || (param->index < 0) || (param->index >= DNS_MAX_SERVERS)) {
		param->result = -1;
		if (param->error_message != NULL) {
			param->error_message = "null pointer or wrong index";
		}
	} else {
#ifdef LWIP
		dns_setserver((u8_t)param->index, (ip_addr_t*)(param->address));
		param->result = 0;
#endif // LWIP
	}

	LLECOM_NETWORK_DEBUG_TRACE("[%s:%u] set DNS result : %d (err %d)\n", __func__, __LINE__, param->result, param->error_code);
}

void LLECOM_NETWORK_IMPL_setGateway_action(MICROEJ_ASYNC_WORKER_job_t* job) {

	ECOM_NETWORK_ip_context_t* param = (ECOM_NETWORK_ip_context_t*) job->params;

	if ((param->netifName == NULL) || (param->address == NULL)) {
		param->result = -1;
		if (param->error_message != NULL) {
			param->error_message = "null pointer";
		}
	} else {
#ifdef LWIP
		struct netif* interface;

		interface = netif_find((char *)param->netifName);

		if (interface != NULL) {
			netif_set_gw(interface, (ip4_addr_t*)(param->address));
			param->result = 0;
		} else {
			param->result = -1;
			if (param->error_message != NULL) {
				param->error_message = "interface not found";
			}
		}
#endif // LWIP
	}

	LLECOM_NETWORK_DEBUG_TRACE("[%s:%u] set gateway result : %d (err %d)\n", __func__, __LINE__, param->result, param->error_code);
}

void LLECOM_NETWORK_IMPL_setIP_action(MICROEJ_ASYNC_WORKER_job_t* job) {

	ECOM_NETWORK_ip_context_t* param = (ECOM_NETWORK_ip_context_t*) job->params;

	if ((param->netifName == NULL) || (param->address == NULL)) {
		param->result = -1;
		if (param->error_message != NULL) {
			param->error_message = "null pointer";
		}
	} else {
#ifdef LWIP
		struct netif* interface;

		interface = netif_find((char *)param->netifName);

		if (interface != NULL) {
			netif_set_ipaddr(interface, (ip4_addr_t*)(param->address));
			param->result = 0;
		} else {
			param->result = -1;
			if (param->error_message != NULL) {
				param->error_message = "interface not found";
			}
		}
#endif // LWIP
	}

	LLECOM_NETWORK_DEBUG_TRACE("[%s:%u] set ip address result : %d (err %d)\n", __func__, __LINE__, param->result, param->error_code);
}

void LLECOM_NETWORK_IMPL_setNetmask_action(MICROEJ_ASYNC_WORKER_job_t* job) {

	ECOM_NETWORK_ip_context_t* param = (ECOM_NETWORK_ip_context_t*) job->params;

	if ((param->netifName == NULL) || (param->address == NULL)) {
		param->result = -1;
		if (param->error_message != NULL) {
			param->error_message = "null pointer";
		}
	} else {
#ifdef LWIP
		struct netif* interface;

		interface = netif_find((char *)param->netifName);

		if (interface != NULL) {
			netif_set_netmask(interface, (ip4_addr_t*)(param->address));
			param->result = 0;
		} else {
			param->result = -1;
			if (param->error_message != NULL) {
				param->error_message = "interface not found";
			}
		}
#endif // LWIP
	}

	LLECOM_NETWORK_DEBUG_TRACE("[%s:%u] set netmask result : %d (err %d)\n", __func__, __LINE__, param->result, param->error_code);
}

void LLECOM_NETWORK_IMPL_useDHCP_action(MICROEJ_ASYNC_WORKER_job_t* job) {

	ECOM_NETWORK_ip_config_t* param = (ECOM_NETWORK_ip_config_t*) job->params;

	if (param->netifName == NULL) {
		param->result = -1;
		if (param->error_message != NULL) {
			param->error_message = "null pointer";
		}
	} else {
		ecom_network_is_static = (param->use == JTRUE) ? 0 : 1;
		param->result = 0;
	}

	LLECOM_NETWORK_DEBUG_TRACE("[%s:%u] use DHCP result : %d (err %d)\n", __func__, __LINE__, param->result, param->error_code);
}

void LLECOM_NETWORK_IMPL_useStaticDNS_action(MICROEJ_ASYNC_WORKER_job_t* job) {

	ECOM_NETWORK_ip_config_t* param = (ECOM_NETWORK_ip_config_t*) job->params;

	if (param->netifName == NULL) {
		param->result = -1;
		if (param->error_message != NULL) {
			param->error_message = "null pointer";
		}
	} else {
		if ((param->use == JTRUE) && !ecom_network_is_static) {
			puts("WARNING: a statically set DNS address will be overridden by DHCP when joining a network");
		}
		if ((param->use == JFALSE) && ecom_network_is_static) {
			puts("WARNING: a dynamically set DNS address will have no effect until enabling the DHCP");
		}
		param->result = 0;
	}

	LLECOM_NETWORK_DEBUG_TRACE("[%s:%u] use static DNS result : %d (err %d)\n", __func__, __LINE__, param->result, param->error_code);
}

void LLECOM_NETWORK_IMPL_setDefault_action(MICROEJ_ASYNC_WORKER_job_t* job) {
	/* No action needed as LwIP handles intrinsically multiple network interfaces,
	 * just is needed to define this function for keep the compatbility with the new feaure of Ecom-Nertwork generic CCO. */
}

#ifdef __cplusplus
}
#endif
