/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * VIRTIO Over Fabrics framework
 *
 * Copyright (c) 2023, Bytedance Inc. All rights reserved.
 *  Author: zhenwei pi <pizhenwei@bytedance.com>
 *
 */
#ifndef _DRIVERS_VIRTIO_VIRTIO_FABRICS_H
#define _DRIVERS_VIRTIO_VIRTIO_FABRICS_H

#include <linux/module.h>
#include <linux/virtio_config.h>
#include <linux/virtio_of.h>
#include <linux/virtio_ring.h>

struct vof_request {
	struct vof_queue *vofq;
	struct virtio_of_command *vofcmd;
	struct virtio_of_completion vofcomp;
	struct completion comp;
};

struct vof_queue {
	struct vof_device *vofdev;
	void (*interrupt)(struct vof_queue *vofq, struct virtio_of_completion *vofcomp);
	struct xarray xa_cmds;
	u32 vring_num;

	struct mutex vring_mutex;
	struct virtqueue *vq;
	struct vring vring;
	u16 last_avail_idx;
	u16 last_used_idx;
};

enum vof_device_state {
	vof_dev_create,
	vof_dev_established,
	vof_dev_disconnected,
	vof_dev_recovery,
	vof_dev_error,
	vof_dev_destroy
};

struct vof_device {
	struct virtio_device vdev;
	struct list_head entry;
	struct vof_transport_ops *ops;
	struct vof_options *opts;

	struct delayed_work recovery_work;
	enum vof_device_state state;
	void (*state_change)(struct vof_device *vofdev, enum vof_device_state state);
	u16 target_id;
	u32 num_queues;
	struct vof_queue *ctrlq;
	struct vof_queue **vringq;
};

static inline struct vof_device *to_vofdev(struct virtio_device *vdev)
{
	return container_of(vdev, struct vof_device, vdev);
}

#define vof_dev_err(vofdev, fmt, ...)							\
	pr_err("%s://%s:%s/%s: " fmt, vofdev->opts->transport, vofdev->opts->taddr,	\
		vofdev->opts->tport, vofdev->opts->tvqn, ##__VA_ARGS__)

#define vof_dev_warn(vofdev, fmt, ...)							\
	pr_warn("%s://%s:%s/%s: " fmt, vofdev->opts->transport, vofdev->opts->taddr,	\
		vofdev->opts->tport, vofdev->opts->tvqn, ##__VA_ARGS__)


#define VOF_TIMEOUT	(3 * HZ)

struct vof_options {
	struct kref ref;
	unsigned int mask;
	char *command;
	char *transport;
	char *taddr;
	char *tport;
	char *tvqn;
	char *iaddr;
	char *iport;
	char *ivqn;
};

struct vof_transport_ops {
	const char *transport;
	enum virtio_of_connection_type oftype;
	struct module *module;
	struct list_head entry;

	/* create a virtio-of device */
	struct vof_device *(*create)(struct vof_options *opts);
	/* destroy a virtio-of device */
	void (*destroy)(struct vof_device *vofdev);

	/* create a queue of a virtio-of device */
	struct vof_queue *(*create_queue)(struct vof_device *vofdev, u32 vring_num);
	/* destroy a queue of a virtio-of device */
	void (*destroy_queue)(struct vof_queue *vofq);

	/* allocate a request of a virtio-of queue */
	struct vof_request *(*alloc_req)(struct vof_queue *vofq, u16 snd_ndesc, u16 rcv_ndesc);
	/* free a request of a virtio-of queue */
	void (*free_req)(struct vof_request *vofreq);
	/* map a vring desc to a virtio-of desc */
	int (*map_req)(struct vof_request *vofreq, u16 idx, struct vring_desc *desc, u16 id, u32 *length);
	/* queue a request into q virtio-of queue, wait the completion asynchronously */
	int (*queue_req)(struct vof_request *vofreq);
};

static inline int vof_status_to_errno(u16 status)
{
	if (status < VIRTIO_OF_EQUIRK)
		return -status;

	return -VIRTIO_OF_EQUIRK;
}

static inline struct vof_request *vof_request_load(struct vof_queue *vofq, u16 command_id)
{
	struct vof_request *vofreq;

	xa_lock(&vofq->xa_cmds);
	vofreq = xa_load(&vofq->xa_cmds, command_id);
	xa_unlock(&vofq->xa_cmds);

	return vofreq;
}

int vof_register_transport(struct vof_transport_ops *ops);
void vof_unregister_transport(struct vof_transport_ops *ops);

#endif
