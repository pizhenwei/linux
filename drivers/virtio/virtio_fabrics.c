// SPDX-License-Identifier: GPL-2.0-only
/*
 * VIRTIO Over Fabrics framework
 *
 * Copyright (c) 2023, Bytedance Inc. All rights reserved.
 *	Author: zhenwei pi <pizhenwei@bytedance.com>
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/parser.h>
#include <linux/miscdevice.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/uuid.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <linux/virtio_ring.h>
#include <linux/virtio_of.h>

#include "virtio_fabrics.h"

#define VOF_MODULE_AUTHOR 	"zhenwei pi <pizhenwei@bytedance.com>"
#define VOF_MODULE_DESC		"VIRTIO Over Fabrics initiator framework"
#define VOF_MODULE_LICENSE	"GPL v2"
#define VOF_MODULE_VERSION	"0.1"

#define VOF_CTRL_TIMEOUT	(3 * HZ)
#define VOF_CTRL_QSIZE		8

/* virtio-of transport */
static LIST_HEAD(vof_transports);
static spinlock_t vof_transports_lock;

/* virtio-of classs and device */
#define VOF_CLASS "virtio-fabrics"
#define VOF_DEVICE "virtio-fabrics"

static struct class *vof_class;
static struct device *vof_device;	/* misc device */
static DEFINE_MUTEX(vof_dev_mutex);

/* the dynamically created devices, protected by vof_dev_mutex */
static LIST_HEAD(vof_devices);

/* workqueue for virtio-of */
static struct workqueue_struct *vof_wq;

#if 1
#define vof_dbg(fmt, ...)
#else
#define vof_dbg(fmt, ...) pr_info("%s: " fmt, __func__, ##__VA_ARGS__)
#endif

enum vof_opt_type {
	VOF_OPT_ERR = 0,
	VOF_OPT_COMMAND,
	VOF_OPT_TRANSPORT,
	VOF_OPT_TADDR,
	VOF_OPT_TPORT,
	VOF_OPT_TVQN,
	VOF_OPT_IADDR,
	VOF_OPT_IPORT,
	VOF_OPT_IVQN
};

static const match_table_t vof_opt_table = {
	{ VOF_OPT_COMMAND,	"command=%s" },
	{ VOF_OPT_TRANSPORT,	"transport=%s" },
	{ VOF_OPT_TADDR,	"taddr=%s" },
	{ VOF_OPT_TPORT,	"tport=%s"},
	{ VOF_OPT_TVQN,		"tvqn=%s"},
	{ VOF_OPT_IADDR,	"iaddr=%s" },
	{ VOF_OPT_IPORT,	"iport=%s"},
	{ VOF_OPT_IVQN,		"ivqn=%s" },
	{ VOF_OPT_ERR,		NULL }
};

static struct vof_options *vof_alloc_options(void)
{
	struct vof_options *opts;

	opts = kzalloc(sizeof(*opts), GFP_KERNEL);
	if (!opts)
		return ERR_PTR(-ENOMEM);

	kref_init(&opts->ref);
	vof_dbg("%px\n", opts);

	return opts;
}

static void vof_free_options(struct kref *ref)
{
	struct vof_options *opts = container_of(ref, struct vof_options, ref);

	kfree(opts->command);
	kfree(opts->transport);
	kfree(opts->taddr);
	kfree(opts->tport);
	kfree(opts->tvqn);
	kfree(opts->iaddr);
	kfree(opts->iport);
	kfree(opts->ivqn);
	kfree(opts);

	vof_dbg("%px\n", opts);
}

static inline void vof_get_options(struct vof_options *opts)
{
	kref_get(&opts->ref);
}

static void vof_put_options(struct vof_options *opts)
{
	if (opts)
		kref_put(&opts->ref, vof_free_options);
}

static struct vof_options *vof_parse_options(const char *buf)
{
	struct vof_options *opts;
	substring_t args[MAX_OPT_ARGS];
	char *options, *o, *p;
	int token, ret = -ENOMEM;

	opts = vof_alloc_options();
	if (!opts)
		return ERR_PTR(-ENOMEM);

	options = o = kstrdup(buf, GFP_KERNEL);
	if (!options)
		goto out;

	while ((p = strsep(&o, ",\n")) != NULL) {
		if (!*p)
			continue;

		token = match_token(p, vof_opt_table, args);
		switch (token) {
#define vof_str_option(field) \
		p = match_strdup(args);	\
		if (!p)			\
			goto out;	\
		kfree(opts->field);	\
		opts->field = p;

		case VOF_OPT_COMMAND:
			vof_str_option(command);
			break;
		case VOF_OPT_TRANSPORT:
			vof_str_option(transport);
			break;
		case VOF_OPT_TADDR:
			vof_str_option(taddr);
			break;
		case VOF_OPT_TPORT:
			vof_str_option(tport);
			break;
		case VOF_OPT_TVQN:
			vof_str_option(tvqn);
			/* sizeof vof_connect_payload::tvqn */
			if (strlen(opts->tvqn) > 256) {
				vof_dbg("parameter '%s' exceeds\n", p);
				ret = -EINVAL;
				goto out;
			}
			break;
		case VOF_OPT_IADDR:
			vof_str_option(iaddr);
			break;
		case VOF_OPT_IPORT:
			vof_str_option(iport);
			break;
		case VOF_OPT_IVQN:
			vof_str_option(ivqn);
			/* sizeof vof_connect_payload::ivqn */
			if (strlen(opts->ivqn) > 256) {
				vof_dbg("parameter '%s' exceeds\n", p);
				ret = -EINVAL;
				goto out;
			}
			break;
		default:
			vof_dbg("invalid parameter '%s'\n", p);
			ret = -EINVAL;
			goto out;
		}
	}

	ret = 0;
out:
	kfree(options);
	if (ret) {
		vof_put_options(opts);
		opts = ERR_PTR(ret);
	}

	return opts;
}

int vof_register_transport(struct vof_transport_ops *ops)
{
	if (!ops->create || !ops->destroy)
		return -EINVAL;

	spin_lock(&vof_transports_lock);
	list_add_tail(&ops->entry, &vof_transports);
	spin_unlock(&vof_transports_lock);
	vof_dbg("register transport '%s'\n", ops->transport);

	return 0;
}
EXPORT_SYMBOL_GPL(vof_register_transport);

void vof_unregister_transport(struct vof_transport_ops *ops)
{
	spin_lock(&vof_transports_lock);
	list_del(&ops->entry);
	spin_unlock(&vof_transports_lock);
	vof_dbg("unregister transport '%s'\n", ops->transport);
}
EXPORT_SYMBOL_GPL(vof_unregister_transport);

static struct vof_transport_ops *vof_get_transport(const char *transport)
{
	struct vof_transport_ops *ops;

	spin_lock(&vof_transports_lock);
	list_for_each_entry(ops, &vof_transports, entry) {
		if (strcmp(ops->transport, transport) == 0) {
			if (!try_module_get(ops->module))
				ops = ERR_PTR(-EBUSY);

			spin_unlock(&vof_transports_lock);
			return ops;
		}
	}
	spin_unlock(&vof_transports_lock);

	return ERR_PTR(-EINVAL);
}

static inline void vof_put_transport(struct vof_transport_ops *ops)
{
	module_put(ops->module);
}

static inline void vof_add_device(struct vof_device *vofdev)
{
	lockdep_assert_held(&vof_dev_mutex);

	list_add_tail(&vofdev->entry, &vof_devices);
	vof_dbg("add device %px", vofdev);
}

static inline void vof_del_device(struct vof_device *vofdev)
{
	lockdep_assert_held(&vof_dev_mutex);

	list_del(&vofdev->entry);
	vof_dbg("del device %px", vofdev);
}

static struct vof_device *vof_get_device(const char *ivqn)
{
	struct vof_device *vofdev;

	lockdep_assert_held(&vof_dev_mutex);

	list_for_each_entry(vofdev, &vof_devices, entry) {
		if (!strcmp(vofdev->opts->ivqn, ivqn))
			return vofdev;
	}

	return NULL;
}

static struct vof_request *vof_alloc_req(struct vof_queue *vofq, u16 snd_ndesc, u16 rcv_ndesc, int command_id)
{
	struct vof_device *vofdev = vofq->vofdev;
	struct xa_limit lmt = { .min = 0, .max = vofq->vring_num - 1 };
	struct vof_request *vofreq;

	vofreq = vofdev->ops->alloc_req(vofq, snd_ndesc, rcv_ndesc);
	WARN_ON_ONCE(!vofreq);
	if (!vofreq)
		return NULL;

	if (command_id >= 0) {
		/* we use *head* as command_id for vring request, this should always be unique */
		BUG_ON(xa_insert(&vofq->xa_cmds, command_id, vofreq, GFP_KERNEL));
	} else {
		if (xa_alloc(&vofq->xa_cmds, (u32 *)&command_id, vofreq, lmt, GFP_KERNEL)) {
			dev_warn(&vofq->vofdev->vdev.dev, "inflight requests exceeds");
			vofdev->ops->free_req(vofreq);
			return NULL;
		}
	}

	init_completion(&vofreq->comp);
	vofreq->vofq = vofq;
	vofreq->vofcmd->common.command_id = cpu_to_le16(command_id);
	vofreq->vofcomp.status = cpu_to_le16(VIRTIO_OF_ETIMEDOUT);

vof_dbg("vofq %px, vofreq %px\n", vofq, vofreq);
	return vofreq;
}

static void vof_free_req(struct vof_queue *vofq, struct vof_request *vofreq)
{
	struct vof_device *vofdev = vofq->vofdev;
	u16 command_id = le16_to_cpu(vofreq->vofcmd->common.command_id);

vof_dbg("vofq %px, vofreq %px\n", vofq, vofreq);
	xa_erase(&vofq->xa_cmds, command_id);
	vofdev->ops->free_req(vofreq);
}

static int vof_connect(struct vof_queue *vofq, u16 target_id, u16 queue_id)
{
	struct vof_device *vofdev = vofq->vofdev;
	struct vof_request *vofreq;
	struct virtio_of_command_connect *cmd;
	struct virtio_of_connect *connect = NULL;
	struct virtio_of_completion *vofcomp;
	struct vring_desc desc;
	u32 length = sizeof(struct virtio_of_connect);
	int ret = -ENOMEM;

	connect = kzalloc(length, GFP_KERNEL);
	if (!connect)
		return -ENOMEM;

	vofreq = vof_alloc_req(vofq, 1, 0, -1);
	if (!vofreq)
		goto free_buf;

	vof_dbg("vofreq %px\n", vofreq);
	strncpy(connect->ivqn, vofdev->opts->ivqn, sizeof(connect->ivqn));
	strncpy(connect->tvqn, vofdev->opts->tvqn, sizeof(connect->tvqn));
	cmd = &vofreq->vofcmd->connect;
	cmd->opcode = cpu_to_le16(virtio_of_op_connect);
	cmd->target_id = cpu_to_le16(target_id);
	cmd->queue_id = cpu_to_le16(queue_id);
	cmd->ndesc = cpu_to_le16(1);
	cmd->oftype = vofdev->ops->oftype;

	desc.addr = cpu_to_virtio64(&vofdev->vdev, virt_to_phys(connect));
	desc.len = cpu_to_virtio32(&vofdev->vdev, length);
	desc.flags = cpu_to_virtio16(&vofdev->vdev, 0);
	desc.next = cpu_to_virtio16(&vofdev->vdev, 0);
	length = 0;
	ret = vofdev->ops->map_req(vofreq, 0, &desc, 0, &length);
	if (ret)
		goto free_buf;

	vofdev->ops->queue_req(vofreq);
	wait_for_completion_timeout(&vofreq->comp, VOF_CTRL_TIMEOUT);

	vofcomp = &vofreq->vofcomp;
	ret = vof_status_to_errno(le16_to_cpu(vofcomp->status));
	if (!ret)
		vofdev->target_id = le16_to_cpu(vofcomp->value.u16);
	else
		vof_dev_err(vofdev, "connect failed: %d", ret);

	vof_free_req(vofq, vofreq);

free_buf:
	kfree(connect);
	return ret;
}

static int vof_get_vendor_id(struct virtio_device *vdev, u32 *vendor_id)
{
	struct vof_device *vofdev = to_vofdev(vdev);
	struct vof_queue *vofq = vofdev->ctrlq;
	struct virtio_of_command_common *cmd;
	struct virtio_of_completion *vofcomp;
	struct vof_request *vofreq;
	int ret;

	vof_dbg("\n");

	vofreq = vof_alloc_req(vofq, 0, 0, -1);
	if (!vofreq)
		return -ENOMEM;

	cmd = &vofreq->vofcmd->common;
	cmd->opcode = cpu_to_le16(virtio_of_op_get_vendor_id);
	vofdev->ops->queue_req(vofreq);
	wait_for_completion_timeout(&vofreq->comp, VOF_CTRL_TIMEOUT);

	vofcomp = &vofreq->vofcomp;
	ret = vof_status_to_errno(le16_to_cpu(vofcomp->status));
	if (!ret)
		*vendor_id = le32_to_cpu(vofcomp->value.u32);
	else
		vof_dev_err(vofdev, "get vendor id failed: %d", ret);

	vof_free_req(vofq, vofreq);

	return 0;
}

static int vof_get_device_id(struct virtio_device *vdev, u32 *device_id)
{
	struct vof_device *vofdev = to_vofdev(vdev);
	struct vof_queue *vofq = vofdev->ctrlq;
	struct virtio_of_command_common *cmd;
	struct virtio_of_completion *vofcomp;
	struct vof_request *vofreq;
	int ret;

	vof_dbg("\n");

	vofreq = vof_alloc_req(vofq, 0, 0, -1);
	if (!vofreq)
		return -ENOMEM;

	cmd = &vofreq->vofcmd->common;
	cmd->opcode = cpu_to_le16(virtio_of_op_get_device_id);
	vofdev->ops->queue_req(vofreq);
	wait_for_completion_timeout(&vofreq->comp, VOF_CTRL_TIMEOUT);

	vofcomp = &vofreq->vofcomp;
	ret = vof_status_to_errno(le16_to_cpu(vofcomp->status));
	if (!ret)
		*device_id = le32_to_cpu(vofcomp->value.u32);
	else
		vof_dev_err(vofdev, "get device id failed: %d", ret);

	vof_free_req(vofq, vofreq);

	return 0;
}

static int vof_get_num_queues(struct virtio_device *vdev)
{
	struct vof_device *vofdev = to_vofdev(vdev);
	struct vof_queue *vofq = vofdev->ctrlq;
	struct virtio_of_command_common *cmd;
	struct virtio_of_completion *vofcomp;
	struct vof_request *vofreq;
	int ret;

	vofreq = vof_alloc_req(vofq, 0, 0, -1);
	if (!vofreq)
		return -ENOMEM;

	cmd = &vofreq->vofcmd->common;
	cmd->opcode = cpu_to_le16(virtio_of_op_get_num_queues);

	vofdev->ops->queue_req(vofreq);
	wait_for_completion_timeout(&vofreq->comp, VOF_CTRL_TIMEOUT);

	vofcomp = &vofreq->vofcomp;
	ret = vof_status_to_errno(le16_to_cpu(vofcomp->status));
	if (!ret)
		ret = le16_to_cpu(vofcomp->value.u16);
	else
		vof_dev_err(vofdev, "get num queues failed: %d", ret);

	vof_free_req(vofq, vofreq);
	return ret;
}

static void vof_get(struct virtio_device *vdev, unsigned int offset, void *buf, unsigned int len)
{
	struct vof_device *vofdev = to_vofdev(vdev);
	struct vof_queue *vofq = vofdev->ctrlq;
	struct virtio_of_command_config *cmd;
	struct virtio_of_completion *vofcomp;
	struct vof_request *vofreq;
	u8 v8;
	u16 v16;
	u32 v32;
	u64 v64;
	int ret;

	vof_dbg("\n");

	vofreq = vof_alloc_req(vofq, 0, 0, -1);
	if (!vofreq)
		return;

	cmd = &vofreq->vofcmd->config;
	cmd->opcode = cpu_to_le16(virtio_of_op_get_config);
	cmd->offset = cpu_to_le16(offset);
	cmd->bytes = len;

	vofdev->ops->queue_req(vofreq);
	wait_for_completion_timeout(&vofreq->comp, VOF_CTRL_TIMEOUT);

	vofcomp = &vofreq->vofcomp;
	ret = vof_status_to_errno(le16_to_cpu(vofcomp->status));
	if (ret) {
		vof_dev_err(vofdev, "get config failed: %d", ret);
		memset(buf, 0x00, len);
	}

	switch (len) {
	case 1:
		v8 = vofcomp->value.u8;
		memcpy(buf, &v8, sizeof(v8));
		break;
	case 2:
		v16 = le16_to_cpu(vofcomp->value.u16);
		memcpy(buf, &v16, sizeof(v16));
		break;
	case 4:
		v32 = le32_to_cpu(vofcomp->value.u32);
		memcpy(buf, &v32, sizeof(v32));
		break;
	case 8:
		v64 = le64_to_cpu(vofcomp->value.u64);
		memcpy(buf, &v64, sizeof(v64));
		break;
	default:
		BUG();
	}

	vof_free_req(vofq, vofreq);
}

static void vof_set(struct virtio_device *vdev, unsigned int offset, const void *buf, unsigned int len)
{
	struct vof_device *vofdev = to_vofdev(vdev);
	struct vof_queue *vofq = vofdev->ctrlq;
	struct virtio_of_command_config *cmd;
	struct virtio_of_completion *vofcomp;
	struct vof_request *vofreq;
	u8 v8;
	u16 v16;
	u32 v32;
	u64 v64;
	int ret;

	vof_dbg("\n");
	vofreq = vof_alloc_req(vofq, 0, 0, -1);
	if (!vofreq)
		return;

	cmd = &vofreq->vofcmd->config;
	cmd->opcode = cpu_to_le16(virtio_of_op_set_config);
	cmd->offset = cpu_to_le16(offset);
	cmd->bytes = len;
	switch (len) {
	case 1:
		memcpy(&v8, buf, sizeof(v8));
		cmd->value.u8 = v8;
		break;
	case 2:
		memcpy(&v16, buf, sizeof(v16));
		cmd->value.u16 = cpu_to_le16(v16);
		break;
	case 4:
		memcpy(&v32, buf, sizeof(v32));
		cmd->value.u32 = cpu_to_le32(v32);
		break;
	case 8:
		memcpy(&v64, buf, sizeof(v64));
		cmd->value.u64 = cpu_to_le64(v64);
		break;
	default:
		BUG();
	}

	vofdev->ops->queue_req(vofreq);
	wait_for_completion_timeout(&vofreq->comp, VOF_CTRL_TIMEOUT);

	vofcomp = &vofreq->vofcomp;
	ret = vof_status_to_errno(le16_to_cpu(vofcomp->status));
	if (ret) {
		vof_dev_err(vofdev, "set config failed: %d", ret);
	}

	vof_free_req(vofq, vofreq);
}

static u32 vof_generation(struct virtio_device *vdev)
{
	struct vof_device *vofdev = to_vofdev(vdev);
	struct vof_queue *vofq = vofdev->ctrlq;
	struct virtio_of_command_common *cmd;
	struct virtio_of_completion *vofcomp;
	struct vof_request *vofreq;
	u32 generation = 0;
	int ret;

	vof_dbg("\n");
	vofreq = vof_alloc_req(vofq, 0, 0, -1);
	if (!vofreq)
		return 0;

	cmd = &vofreq->vofcmd->common;
	cmd->opcode = cpu_to_le16(virtio_of_op_get_generation);

	vofdev->ops->queue_req(vofreq);
	wait_for_completion_timeout(&vofreq->comp, VOF_CTRL_TIMEOUT);

	vofcomp = &vofreq->vofcomp;
	ret = vof_status_to_errno(le16_to_cpu(vofcomp->status));
	if (!ret)
		generation = le32_to_cpu(vofcomp->value.u32);
	else
		vof_dev_err(vofdev, "get generation failed: %d", ret);

	vof_free_req(vofq, vofreq);

	return generation;
}

static u8 vof_get_status(struct virtio_device *vdev)
{
	struct vof_device *vofdev = to_vofdev(vdev);
	struct vof_queue *vofq = vofdev->ctrlq;
	struct virtio_of_command_status *cmd;
	struct virtio_of_completion *vofcomp;
	struct vof_request *vofreq;
	u8 status = VIRTIO_CONFIG_S_FAILED;
	int ret;

	vof_dbg("\n");
	/* once we are destroying the fabric device, network is going to disconnect */
	if (vofdev->state == vof_dev_destroy)
		return 0;

	vofreq = vof_alloc_req(vofq, 0, 0, -1);
	if (!vofreq)
		return status;

	cmd = &vofreq->vofcmd->status;
	cmd->opcode = cpu_to_le16(virtio_of_op_get_status);

	vofdev->ops->queue_req(vofreq);
	wait_for_completion_timeout(&vofreq->comp, VOF_CTRL_TIMEOUT);

	vofcomp = &vofreq->vofcomp;
	ret = vof_status_to_errno(le16_to_cpu(vofcomp->status));
	if (!ret)
		status = vofcomp->value.u8;
	else
		vof_dev_err(vofdev, "get status failed: %d", ret);

	vof_free_req(vofq, vofreq);

	return status;
}

static void vof_set_status(struct virtio_device *vdev, u8 status)
{
	struct vof_device *vofdev = to_vofdev(vdev);
	struct vof_queue *vofq = vofdev->ctrlq;
	struct virtio_of_command_status *cmd;
	struct virtio_of_completion *vofcomp;
	struct vof_request *vofreq;
	int ret;

	vof_dbg("\n");
	if (vofdev->state == vof_dev_destroy)
		return;

	vofreq = vof_alloc_req(vofq, 0, 0, -1);
	if (!vofreq)
		return;

	cmd = &vofreq->vofcmd->status;
	cmd->opcode = cpu_to_le16(virtio_of_op_set_status);
	cmd->status = cpu_to_le32(status);

	vofdev->ops->queue_req(vofreq);
	wait_for_completion_timeout(&vofreq->comp, VOF_CTRL_TIMEOUT);

	vofcomp = &vofreq->vofcomp;
	ret = vof_status_to_errno(le16_to_cpu(vofcomp->status));
	if (ret)
		vof_dev_err(vofdev, "set status failed: %d", ret);

	vof_free_req(vofq, vofreq);
}

static int vof_get_queue_size(struct virtio_device *vdev, __u16 queue_id)
{
	struct vof_device *vofdev = to_vofdev(vdev);
	struct vof_queue *vofq = vofdev->ctrlq;
	struct virtio_of_command_queue *cmd;
	struct virtio_of_completion *vofcomp;
	struct vof_request *vofreq;
	u16 size = 0;
	int ret;

	vof_dbg("\n");

	vofreq = vof_alloc_req(vofq, 0, 0, -1);
	if (!vofreq)
		return -ENOMEM;

	cmd = &vofreq->vofcmd->queue;
	cmd->opcode = cpu_to_le16(virtio_of_op_get_queue_size);
	cmd->queue_id = cpu_to_le16(queue_id);

	vofdev->ops->queue_req(vofreq);
	wait_for_completion_timeout(&vofreq->comp, VOF_CTRL_TIMEOUT);

	vofcomp = &vofreq->vofcomp;
	ret = vof_status_to_errno(le16_to_cpu(vofcomp->status));
	if (!ret)
		size = le16_to_cpu(vofcomp->value.u16);
	else
		vof_dev_err(vofdev, "get queue size failed: %d", ret);

	vof_free_req(vofq, vofreq);

	return size;
}

static void vof_reset(struct virtio_device *vdev)
{
	vof_set_status(vdev, 0);
}

static u64 vof_get_features(struct virtio_device *vdev)
{
	struct vof_device *vofdev = to_vofdev(vdev);
	struct vof_queue *vofq = vofdev->ctrlq;
	struct virtio_of_command_feature *cmd;
	struct virtio_of_completion *vofcomp;
	struct vof_request *vofreq;
	u64 feature = 0;
	int ret;

	vof_dbg("\n");
	vofreq = vof_alloc_req(vofq, 0, 0, -1);
	if (!vofreq)
		return 0;

	cmd = &vofreq->vofcmd->feature;
	cmd->opcode = cpu_to_le16(virtio_of_op_get_device_feature);
	cmd->feature_select = cpu_to_le32(0);

	vofdev->ops->queue_req(vofreq);
	wait_for_completion_timeout(&vofreq->comp, VOF_CTRL_TIMEOUT);

	vofcomp = &vofreq->vofcomp;
	ret = vof_status_to_errno(le16_to_cpu(vofcomp->status));
	if (!ret)
		feature = le64_to_cpu(vofcomp->value.u64);
	else
		vof_dev_err(vofdev, "get device features failed: %d", ret);
	//TODO disable VIRTIO_F_ACCESS_PLATFORM,VIRTIO_RING_F_INDIRECT_DESC,VIRTIO_F_ORDER_PLATFORM,VIRTIO_F_RING_PACKED

	vof_free_req(vofq, vofreq);

	return feature;
}

static int vof_finalize_features(struct virtio_device *vdev)
{
	struct vof_device *vofdev = to_vofdev(vdev);
	struct vof_queue *vofq = vofdev->ctrlq;
	struct virtio_of_command_feature *cmd;
	struct virtio_of_completion *vofcomp;
	struct vof_request *vofreq;
	int ret;

	vof_dbg("\n");
	vring_transport_features(vdev);

	vofreq = vof_alloc_req(vofq, 0, 0, -1);
	if (!vofreq)
		return -ENOMEM;

	cmd = &vofreq->vofcmd->feature;
	cmd->opcode = cpu_to_le16(virtio_of_op_set_driver_feature);
	cmd->feature_select = cpu_to_le32(0);
	cmd->value = cpu_to_le64(vdev->features);

	vofdev->ops->queue_req(vofreq);
	wait_for_completion_timeout(&vofreq->comp, VOF_CTRL_TIMEOUT);

	vofcomp = &vofreq->vofcomp;
	ret = vof_status_to_errno(le16_to_cpu(vofcomp->status));
	if (ret)
		vof_dev_err(vofdev, "set driver features failed: %d", ret);

	vof_free_req(vofq, vofreq);

	return ret;
}

static int vof_handle_vq(struct virtqueue *vq)
{
	struct vof_device *vofdev = to_vofdev(vq->vdev);
	struct vof_queue *vofq = vofdev->vringq[vq->index];
	struct vof_request *vofreq;
	struct virtio_of_command_vring *cmd;
	struct vring *vring = &vofq->vring;
	struct vring_desc *desc;
	u32 total = 0;
	u16 avail_idx, last_avail_idx, snd_ndesc = 0, rcv_ndesc = 0, i = 0;
	u16 head, flags, next;
	int ret;

	virtio_mb(true);
	avail_idx = virtio16_to_cpu(&vofdev->vdev, vring->avail->idx);
	last_avail_idx = vofq->last_avail_idx;
	if (last_avail_idx == avail_idx) {
		return -EAGAIN;
	}

	vofq->last_avail_idx++;

	head = vring->avail->ring[last_avail_idx & (vring->num - 1)];
	head = virtio16_to_cpu(&vofdev->vdev, head);
	BUG_ON(unlikely(head >= vring->num));
	//vof_dbg("command_id 0x%x, last_avail_idx %d\n", head, last_avail_idx);

	/* count ndesc firstly */
	next = head;
	do {
		desc = vring->desc + next;
		flags = virtio16_to_cpu(vq->vdev, desc->flags);
		if (flags & VRING_DESC_F_WRITE)
			rcv_ndesc++;
		else
			snd_ndesc++;
		next = virtio16_to_cpu(vq->vdev, desc->next);
	} while (flags & VRING_DESC_F_NEXT);

	vofreq = vof_alloc_req(vofq, snd_ndesc, rcv_ndesc, head);
	if (!vofreq)
		return -ENOMEM;

	/* map virtio desc to virtio-of desc */
	next = head;
	do {
		desc = vring->desc + next;
		ret = vofdev->ops->map_req(vofreq, i++, desc, next, &total);
		next = virtio16_to_cpu(vq->vdev, desc->next);
		flags = virtio16_to_cpu(vq->vdev, desc->flags);
	} while (flags & VRING_DESC_F_NEXT);

	cmd = &vofreq->vofcmd->vring;
	cmd->opcode = cpu_to_le16(virtio_of_op_vring);
	cmd->command_id = cpu_to_le16(head);
	cmd->length = cpu_to_le32(total);
	cmd->ndesc = cpu_to_le16(snd_ndesc + rcv_ndesc);
	vofdev->ops->queue_req(vofreq);

	return 0;
}

static bool vof_notify(struct virtqueue *vq)
{
	struct vof_device *vofdev = to_vofdev(vq->vdev);
	struct vof_queue *vofq = vofdev->vringq[vq->index];
	int ret;

	if (!mutex_trylock(&vofq->vring_mutex))
		return true;

	do {
		ret = vof_handle_vq(vq);
	} while (!ret);

	mutex_unlock(&vofq->vring_mutex);

	return true;
}

static void vof_del_vqs(struct virtio_device *vdev)
{
	struct vof_device *vofdev = to_vofdev(vdev);
	struct vof_queue *vofq;
	int i;

	for (i = 0; i < vofdev->num_queues; i++) {
		vofq = vofdev->vringq[i];
		if (!vofq)
			continue;

		vofdev->ops->destroy_queue(vofq);
		vring_del_virtqueue(vofq->vq);
		vofdev->vringq[i] = NULL;
		/* is there any inflight request in virtqueue? */
		BUG_ON(!xa_empty(&vofq->xa_cmds));
		xa_destroy(&vofq->xa_cmds);
	}
}

static void vof_interrupt(struct vof_queue *vofq, struct virtio_of_completion *vofcomp)
{
	struct vof_request *vofreq;
	struct vring *vring = &vofq->vring;
	struct vring_avail *avail = vring->avail;
	struct vring_used *used = vring->used;
	struct vring_used_elem *elem;
	u16 command_id, opcode;
	u16 last_used_idx, flags;
	u32 len;

	command_id = le16_to_cpu(vofcomp->command_id);
	vofreq = vof_request_load(vofq, command_id);
	vof_dbg("command_id %d, vofreq %px\n", command_id, vofreq);
	if (unlikely(!vofreq)) {
		//TODO handle error
		dev_err(&vofq->vofdev->vdev.dev, "unexpected command id");
		return;
	}

	memcpy(&vofreq->vofcomp, vofcomp, sizeof(*vofcomp));
	opcode = le16_to_cpu(vofreq->vofcmd->common.opcode);
	vof_dbg("command_id %d, opcode 0x%x\n", command_id, opcode);
	if (opcode == virtio_of_op_vring) {
		last_used_idx = vofq->last_used_idx;
		elem = &used->ring[last_used_idx & (vring->num - 1)];
		elem->id = cpu_to_virtio32(&vofq->vofdev->vdev, command_id);
		len = le32_to_cpu(vofreq->vofcomp.value.u32);
		elem->len = cpu_to_virtio32(&vofq->vofdev->vdev, len);
		vof_free_req(vofq, vofreq);

		vofq->last_used_idx++;
		used->idx = cpu_to_virtio16(&vofq->vofdev->vdev, vofq->last_used_idx);
		virtio_mb(true);
		flags = cpu_to_virtio16(&vofq->vofdev->vdev, avail->flags);
		vof_dbg("command_id 0x%x, last_used_idx %d, len %d, flags 0x%x\n", command_id, last_used_idx, len, flags);
		if (!(flags & VRING_AVAIL_F_NO_INTERRUPT))
			vring_interrupt(0, vofq->vq);  //TODO use tcp queue irq id
	} else {
		complete(&vofreq->comp);
	}
}

static struct vof_queue *vof_create_queue(struct vof_device *vofdev, u16 target_id, u16 queue_id, u32 vring_num)
{
	struct vof_queue *vofq;
	int ret;

	vofq = vofdev->ops->create_queue(vofdev, vring_num);
	if (IS_ERR(vofq))
		return vofq;

	vofq->interrupt = vof_interrupt;
	xa_init_flags(&vofq->xa_cmds, XA_FLAGS_ALLOC);
	mutex_init(&vofq->vring_mutex);
	ret = vof_connect(vofq, target_id, queue_id);
	if (ret < 0)
		goto destroy_queue;

	return vofq;

destroy_queue:
	vofdev->ops->destroy_queue(vofq);

	return ERR_PTR(ret);
}

static struct virtqueue *vof_setup_vq(struct virtio_device *vdev, unsigned int index,
		void (*callback)(struct virtqueue *vq),
		const char *name, bool ctx)
{
	struct vof_device *vofdev = to_vofdev(vdev);
	struct vof_queue *vofq;
	struct virtqueue *vq;
	void *vring_addr;
	int qsize;
	int ret;

	BUG_ON(index >= vofdev->num_queues);
	BUG_ON(vofdev->vringq[index]);

	qsize = vof_get_queue_size(vdev, index);
	if (!is_power_of_2(qsize)) {
		dev_err(&vofdev->vdev.dev, "bad queue size %u", qsize);
		return ERR_PTR(-EINVAL);
	}
	vof_dbg("queue %d, queue size %d\n", index, qsize);

	vofq = vof_create_queue(vofdev, vofdev->target_id, index, qsize);
	if (IS_ERR(vofq))
		return ERR_PTR(PTR_ERR(vofq));

	vq = vring_create_virtqueue(index, qsize, SMP_CACHE_BYTES, vdev,
			true, true, ctx, vof_notify, callback, name);
	if (!vq) {
		ret = -ENOMEM;
		goto destroy_queue;
	}

	vring_addr = phys_to_virt(virtqueue_get_desc_addr(vq));
	vring_init(&vofq->vring, qsize, vring_addr, SMP_CACHE_BYTES);
	vofq->vq = vq;
	vofdev->vringq[index] = vofq;

	return vq;

destroy_queue:
	vofdev->ops->destroy_queue(vofq);

	return ERR_PTR(ret);
}

static int vof_find_vqs(struct virtio_device *vdev, unsigned int nvqs,
		struct virtqueue *vqs[],
		vq_callback_t *callbacks[],
		const char * const names[],
		const bool *ctx,
		struct irq_affinity *desc)
{
	struct vof_device *vofdev = to_vofdev(vdev);
	int i;

	for (i = 0; i < nvqs; ++i) {
		if (!names[i]) {
			vqs[i] = NULL;
			continue;
		}

		vqs[i] = vof_setup_vq(vdev, i, callbacks[i], names[i],
				ctx ? ctx[i] : false);
		if (IS_ERR(vqs[i])) {
			dev_err(&vdev->dev, "setup vq %d failed: %d", i, (int)PTR_ERR(vqs[i]));
			vof_del_vqs(vdev);
			return PTR_ERR(vqs[i]);
		}
	}

	/* all the virtqueues connectect successfully */
	vofdev->state = vof_dev_established;

	return 0;
}

static const char *vof_bus_name(struct virtio_device *vdev)
{
	return "virtio-fabrics";
}

static const struct virtio_config_ops vof_config_ops = {
	.get			= vof_get,
	.set			= vof_set,
	.generation		= vof_generation,
	.get_status		= vof_get_status,
	.set_status		= vof_set_status,
	.reset			= vof_reset,
	.find_vqs		= vof_find_vqs,
	.del_vqs		= vof_del_vqs,
	.get_features		= vof_get_features,
	.finalize_features	= vof_finalize_features,
	.bus_name		= vof_bus_name,
};

static int vof_create_ctrlq(struct vof_device *vofdev)
{
	int ret;

	vofdev->ctrlq = vof_create_queue(vofdev, 0xffff, 0, VOF_CTRL_QSIZE);
	if (IS_ERR(vofdev->ctrlq))
		return PTR_ERR(vofdev->ctrlq);

	ret = vof_get_num_queues(&vofdev->vdev);
	if (ret <= 0) {
		/* TODO: virtio spec define 0 queue of a device, but we can't do anything */
		vof_dev_err(vofdev, "get num queues from failed: %d", ret);
		goto error;
	}

	vofdev->num_queues = ret;
	vofdev->vringq = kcalloc(vofdev->num_queues, sizeof(struct vof_queue *), GFP_KERNEL);
	if (!vofdev->vringq) {
		ret = -ENOMEM;
		goto error;
	}

	return 0;

error:
	vofdev->ops->destroy_queue(vofdev->ctrlq);

	return ret;
}

static void vof_release_device(struct device *dev)
{
	struct virtio_device *vdev = dev_to_virtio(dev);
	struct vof_device *vofdev = to_vofdev(vdev);
	struct vof_transport_ops *ops = vofdev->ops;
	struct xarray *xa_cmds = &vofdev->ctrlq->xa_cmds;
	struct vof_request *vofreq;
	unsigned long command_id;

	xa_lock(xa_cmds);
	xa_for_each(xa_cmds, command_id, vofreq) {
pr_err("TODO: vof_release_device\n");	//TODO
	}
	xa_unlock(xa_cmds);
	xa_destroy(xa_cmds);
	ops->destroy_queue(vofdev->ctrlq);
	ops->destroy(vofdev);
}

static void vof_device_state_change(struct vof_device *vofdev, enum vof_device_state new_state)
{
vof_dev_warn(vofdev, "state change from %d to %d\n", vofdev->state, new_state);
	if (vofdev->state == new_state)
		return;

	if (new_state == vof_dev_disconnected) {
		switch (vofdev->state) {
		case vof_dev_create:
			vofdev->state = vof_dev_error;
			return;
		case vof_dev_established:
			vofdev->state = vof_dev_recovery;
			//TODO queue recovery work
			return;
		default:
			break;
		}
	}

	vofdev->state = new_state;
}

static int vof_create_device(struct vof_options *opts)
{
	struct vof_transport_ops *ops;
	struct vof_device *vofdev;
	u32 vendor_id, device_id;
	int ret = 0;

	lockdep_assert_held(&vof_dev_mutex);

	if (!opts->transport || !opts->taddr || !opts->tport || !opts->tvqn || !opts->ivqn)
		return -EINVAL;

	if (vof_get_device(opts->ivqn)) {
		pr_info("IVQN '%s' already in use\n", opts->ivqn);
		return -EBUSY;
	}

	request_module("virtio-%s", opts->transport);
	ops = vof_get_transport(opts->transport);
	if (IS_ERR(ops)) {
		pr_info("couldn't find transport '%s'\n", opts->transport);
		return PTR_ERR(ops);
	}

	vof_get_options(opts);
	vofdev = ops->create(opts);
	if (IS_ERR(vofdev)) {
		ret = PTR_ERR(vofdev);
		goto put_options;
	}

	vofdev->state = vof_dev_create;
	vofdev->state_change = vof_device_state_change;
	vofdev->ops = ops;
	ret = vof_create_ctrlq(vofdev);
	if (ret)
		goto destroy_dev;

	ret = vof_get_vendor_id(&vofdev->vdev, &vendor_id);
	if (ret < 0) {
		vof_dev_err(vofdev, "get vendor id failed: %d", ret);
		goto destroy_dev;
	}

	ret = vof_get_device_id(&vofdev->vdev, &device_id);
	if (ret < 0) {
		vof_dev_err(vofdev, "get device id failed: %d", ret);
		goto destroy_dev;
	}

	vofdev->vdev.id.vendor = vendor_id;
	vofdev->vdev.id.device = device_id;
	vofdev->vdev.config = &vof_config_ops;
	vofdev->vdev.dev.parent = vof_device;
	vofdev->vdev.dev.release = vof_release_device;
	ret = register_virtio_device(&vofdev->vdev);
	if (ret)
		goto destroy_dev;

	vof_add_device(vofdev);

	return 0;

destroy_dev:
	ops->destroy(vofdev);

put_options:
	vof_put_options(opts);
	vof_put_transport(ops);

	return ret;
}

static int vof_destroy_device(struct vof_options *opts)
{
	struct vof_device *vofdev;
	struct vof_transport_ops *ops;

	lockdep_assert_held(&vof_dev_mutex);

	vofdev = vof_get_device(opts->ivqn);
	if (!vofdev)
		return -EINVAL;

	ops = vofdev->ops;
	vofdev->state = vof_dev_destroy;
	unregister_virtio_device(&vofdev->vdev);
	vof_put_transport(ops);
	vof_del_device(vofdev);
	vof_put_options(vofdev->opts);

	return 0;
}

static ssize_t vof_dev_write(struct file *file, const char __user *ubuf, size_t count, loff_t *pos)
{
	struct seq_file *seq_file = file->private_data;
	struct vof_options *opts;
	const char *buf;
	int ret = 0;

	if (count > PAGE_SIZE)
		return -ENOMEM;

	buf = memdup_user_nul(ubuf, count);
	if (IS_ERR(buf))
		return PTR_ERR(buf);

	opts = vof_parse_options(buf);
	if (IS_ERR(opts)) {
		ret = PTR_ERR(opts);
		goto freebuf;
	}

	mutex_lock(&vof_dev_mutex);
	if (seq_file->private) {
		ret = -EINVAL;
		goto unlock;
	}

	if (!strcmp(opts->command, "create"))
		ret = vof_create_device(opts);
	else if (!strcmp(opts->command, "destroy"))
		ret = vof_destroy_device(opts);
	else
		ret = -EINVAL;

	seq_file->private = ERR_PTR(-EINVAL);

unlock:
	mutex_unlock(&vof_dev_mutex);
	vof_put_options(opts);

freebuf:
	kfree(buf);

	return ret ? ret : count;
}

static int vof_dev_show(struct seq_file *seq_file, void *private)
{
	const struct match_token *tok;
	int idx;

	mutex_lock(&vof_dev_mutex);
	for (idx = 0; idx < ARRAY_SIZE(vof_opt_table); idx++) {
		tok = &vof_opt_table[idx];
		if (tok->token == VOF_OPT_ERR)
			continue;
		if (idx)
			seq_puts(seq_file, ",");
		seq_puts(seq_file, tok->pattern);
	}
	seq_puts(seq_file, "\n");
	mutex_unlock(&vof_dev_mutex);

	return 0;
}

static int vof_dev_open(struct inode *inode, struct file *file)
{
	file->private_data = NULL;
	return single_open(file, vof_dev_show, NULL);
}

static int vof_dev_release(struct inode *inode, struct file *file)
{
	return single_release(inode, file);
}

static const struct file_operations vof_dev_fops = {
	.owner= THIS_MODULE,
	.write= vof_dev_write,
	.read = seq_read,
	.open = vof_dev_open,
	.release = vof_dev_release,
};

static struct miscdevice vof_misc = {
	.minor= MISC_DYNAMIC_MINOR,
	.name = VOF_DEVICE,
	.fops = &vof_dev_fops,
};

static void inline vof_build_check(void)
{
	BUILD_BUG_ON(sizeof(struct virtio_of_command) != sizeof(struct virtio_of_command_common));
	BUILD_BUG_ON(sizeof(struct virtio_of_command) != sizeof(struct virtio_of_command_connect));
	BUILD_BUG_ON(sizeof(struct virtio_of_command) != sizeof(struct virtio_of_command_feature));
	BUILD_BUG_ON(sizeof(struct virtio_of_command) != sizeof(struct virtio_of_command_queue));
	BUILD_BUG_ON(sizeof(struct virtio_of_command) != sizeof(struct virtio_of_command_config));
	BUILD_BUG_ON(sizeof(struct virtio_of_command) != sizeof(struct virtio_of_command_status));
	BUILD_BUG_ON(sizeof(struct virtio_of_command) != sizeof(struct virtio_of_command_vring));
	BUILD_BUG_ON(sizeof(struct virtio_of_connect) != 1024);
}

static int __init vof_init(void)
{
	int ret;

	vof_build_check();

	vof_class = class_create(THIS_MODULE, VOF_CLASS);
	if (IS_ERR(vof_class)) {
		pr_err("couldn't create class '%s'\n", VOF_CLASS);
		ret = PTR_ERR(vof_class);
		goto err;
	}

	vof_device = device_create(vof_class, NULL, MKDEV(0, 0), NULL, "ctl");
	if (IS_ERR(vof_device)) {
		pr_err("couldn't create '%s'\n", VOF_DEVICE);
		ret = PTR_ERR(vof_device);
		goto destroy_class;
	}

	ret = misc_register(&vof_misc);
	if (ret) {
		pr_err("couldn't register misc device: %d\n", ret);
		goto destroy_device;
	}

	spin_lock_init(&vof_transports_lock);
	vof_wq = alloc_workqueue("virtio-of_wq", WQ_MEM_RECLAIM, 0);
	if (!vof_wq) {
		ret = -ENOMEM;
		goto destroy_misc;
	}

	return 0;

destroy_misc:
	misc_deregister(&vof_misc);

destroy_device:
	device_destroy(vof_class, MKDEV(0, 0));

destroy_class:
	class_destroy(vof_class);

err:
	return ret;
}

static void __exit vof_exit(void)
{
	destroy_workqueue(vof_wq);
	misc_deregister(&vof_misc);
	device_destroy(vof_class, MKDEV(0, 0));
	class_destroy(vof_class);
}

module_init(vof_init);
module_exit(vof_exit);

MODULE_AUTHOR(VOF_MODULE_AUTHOR);
MODULE_DESCRIPTION(VOF_MODULE_DESC);
MODULE_LICENSE(VOF_MODULE_LICENSE);
MODULE_VERSION(VOF_MODULE_VERSION);
