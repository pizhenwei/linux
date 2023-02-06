// SPDX-License-Identifier: GPL-2.0-only
/*
 * VIRTIO Over RDMA initiator
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
#include <linux/inet.h>
#include <linux/virtio_of.h>
#include <rdma/rdma_cm.h>

#include "virtio_fabrics.h"

#define VRDMA_MODULE_AUTHOR	"zhenwei pi <pizhenwei@bytedance.com>"
#define VRDMA_MODULE_DESC	"VIRTIO Over RDMA initiator"
#define VRDMA_MODULE_LICENSE	"GPL v2"
#define VRDMA_MODULE_VERSION	"0.1"

struct vrdma_completion {
	struct virtio_of_completion vofcomp;
	struct ib_cqe cqe;
	u64 dma;
	struct vrdma_queue *vrdmaq;
};

struct vrdma_mem {
	struct scatterlist sg;
	struct ib_cqe cqe;
	struct ib_mr *mr;
};

struct vrdma_request {
	struct vof_request vofreq;
	struct virtio_of_vring_desc *vofdescs;
	u16 ndesc;
	u64 dma;		/* DMA address for vofcmd + vofdescs */
	struct ib_cqe cqe;	/* CQE for command */
	struct vrdma_mem *vmem;
};

struct vrdma_queue {
	struct vof_queue vofq;
	struct work_struct work;
	struct completion cm_comp;
	struct rdma_cm_id *cm_id;
	struct ib_pd *pd;
	struct ib_cq *cq;
	struct vrdma_completion *vrdmacomp;
	int state;
};

struct vrdma_device {
	struct vof_device vofdev;
	struct sockaddr_storage taddr;
	struct sockaddr_storage iaddr;
};

static inline struct vrdma_request *to_vrdmareq(struct vof_request *vofreq)
{
	return container_of(vofreq, struct vrdma_request, vofreq);
}

static inline struct vrdma_queue *to_vrdmaq(struct vof_queue *vofq)
{
	return container_of(vofq, struct vrdma_queue, vofq);
}

static inline struct vrdma_device *to_vrdmadev(struct vof_device *vofdev)
{
	return container_of(vofdev, struct vrdma_device, vofdev);
}

static int vrdma_post_recv(struct vrdma_queue *vrdmaq, struct vrdma_completion *vrdmacomp)
{
	struct ib_recv_wr wr;
	struct ib_sge sge;
	int ret;

	sge.addr   = vrdmacomp->dma;
	sge.length = sizeof(struct virtio_of_completion);
	sge.lkey   = vrdmaq->pd->local_dma_lkey;

	wr.next     = NULL;
	wr.wr_cqe   = &vrdmacomp->cqe;
	wr.sg_list  = &sge;
	wr.num_sge  = 1;

	ret = ib_post_recv(vrdmaq->cm_id->qp, &wr, NULL);
	if (unlikely(ret)) {
		dev_err(&vrdmaq->vofq.vofdev->vdev.dev, "ib_post_recv failed: %d\n", ret);
	}

	return ret;
}

static void vrdma_recv_done(struct ib_cq *cq, struct ib_wc *wc)
{
	struct vrdma_completion *vrdmacomp = container_of(wc->wr_cqe, struct vrdma_completion, cqe);
	struct vrdma_queue *vrdmaq = vrdmacomp->vrdmaq;
	struct vof_queue *vofq = &vrdmaq->vofq;
	char *reason;

	if (unlikely(wc->status != IB_WC_SUCCESS)) {
		reason = "rdma recv status error";
		goto error;
	}

	if (unlikely(wc->byte_len != sizeof(struct virtio_of_completion))) {
		reason = "rdma recv unexpected completion length";
		goto error;
	}

	vofq->interrupt(vofq, &vrdmacomp->vofcomp);
	vrdma_post_recv(vrdmaq, vrdmacomp);

	return;

error:
	return;
}

static inline enum dma_data_direction vrdma_dma_direction(__u16 flags)
{
	if (flags & VRING_DESC_F_WRITE)
		return DMA_FROM_DEVICE;
	else
		return DMA_TO_DEVICE;
}

static void vrdma_mem_dereg(struct vrdma_queue *vrdmaq, struct vrdma_mem *vmem, __u16 flags)
{
	struct ib_device *ibdev = vrdmaq->cm_id->device;
	enum dma_data_direction dir = vrdma_dma_direction(flags);

	ib_dereg_mr(vmem->mr);
	ib_dma_unmap_sg(ibdev, &vmem->sg, 1, dir);
}

static void vrdma_mem_reg_done(struct ib_cq *cq, struct ib_wc *wc)
{
}

static int vrdma_mem_reg(struct vrdma_queue *vrdmaq, struct vrdma_mem *vmem, void *vaddr, int length, __u16 flags)
{
	struct ib_device *ibdev = vrdmaq->cm_id->device;
	struct ib_mr *mr;
	struct ib_reg_wr reg_wr;
	enum dma_data_direction dir = vrdma_dma_direction(flags);
	int access = IB_ACCESS_LOCAL_WRITE;
	int ret;

	if (dir == DMA_TO_DEVICE)
		access |= IB_ACCESS_REMOTE_READ;
	else if (dir == DMA_FROM_DEVICE)
		access |= IB_ACCESS_REMOTE_WRITE;

	mr = ib_alloc_mr(vrdmaq->pd, IB_MR_TYPE_MEM_REG, length);
	if (IS_ERR(mr)) {
		dev_err(&vrdmaq->vofq.vofdev->vdev.dev, "ib_alloc_mr length(%d) failed: %d\n", length, (int)PTR_ERR(mr));
		return PTR_ERR(mr);
	}

	sg_init_one(&vmem->sg, vaddr, length);
	ret = ib_dma_map_sg(ibdev, &vmem->sg, 1, dir);
	if (ret != 1) {
		dev_err(&vrdmaq->vofq.vofdev->vdev.dev, "ib_dma_map_sg length(%d) with dir(%d) failed: %d\n", length, dir, ret);
		ret = ret < 0 ? ret : -EIO;
		goto dereg_mr;
	}

	ret = ib_map_mr_sg(mr, &vmem->sg, 1, NULL, SZ_4K);
	if (ret != 1) {
		dev_err(&vrdmaq->vofq.vofdev->vdev.dev, "ib_map_mr_sg length(%d) with dir(%d) failed: %d\n", length, dir, ret);
		ret = ret < 0 ? ret : -EINVAL;
		goto unmap_sg;
	}

	vmem->mr = mr;
	vmem->cqe.done = vrdma_mem_reg_done;

	memset(&reg_wr, 0, sizeof(struct ib_reg_wr));
	reg_wr.wr.next = NULL;
	reg_wr.wr.opcode = IB_WR_REG_MR;
	reg_wr.wr.wr_cqe = &vmem->cqe;
	reg_wr.wr.num_sge = 0;
	reg_wr.wr.send_flags = IB_SEND_SIGNALED;
	reg_wr.mr = mr;
	reg_wr.key = mr->rkey;
	reg_wr.access = access;

	ret = ib_post_send(vrdmaq->cm_id->qp, &reg_wr.wr, NULL);
	if (ret) {
		dev_err(&vrdmaq->vofq.vofdev->vdev.dev, "ib_post_send reg MR failed: %d\n", ret);
		goto unmap_sg;
	}

	return 0;

unmap_sg:
	ib_dma_unmap_sg(ibdev, &vmem->sg, 1, dir);

dereg_mr:
	ib_dereg_mr(mr);

	return ret;
}

static void vrdma_free_completion(struct vrdma_queue *vrdmaq, u32 size)
{
	struct vrdma_completion *vrdmacomp;
	struct ib_device *ibdev = vrdmaq->cm_id->device;
	int i;

	for (i = 0; i < size; i++) {
		vrdmacomp = vrdmaq->vrdmacomp + i;
		ib_dma_unmap_single(ibdev, vrdmacomp->dma, sizeof(struct vrdma_completion), DMA_FROM_DEVICE);
	}

	kfree(vrdmaq->vrdmacomp);
	vrdmaq->vrdmacomp = NULL;
}

static int vrdma_alloc_completion(struct vrdma_queue *vrdmaq)
{
	struct vrdma_completion *vrdmacomp;
	struct ib_device *ibdev = vrdmaq->cm_id->device;
	u32 vring_num = vrdmaq->vofq.vring_num;
	int i;

	vrdmaq->vrdmacomp = kzalloc(vring_num * sizeof(struct vrdma_completion), GFP_KERNEL);
	if (!vrdmaq->vrdmacomp)
		return -ENOMEM;

	for (i = 0; i < vring_num; i++) {
		vrdmacomp = vrdmaq->vrdmacomp + i;
		vrdmacomp->cqe.done = vrdma_recv_done;
		vrdmacomp->vrdmaq = vrdmaq;
		vrdmacomp->dma = ib_dma_map_single(ibdev, &vrdmacomp->vofcomp, sizeof(struct virtio_of_completion), DMA_FROM_DEVICE);
		if (ib_dma_mapping_error(ibdev, vrdmacomp->dma)) {
			pr_err("ib_dma_map_single for completion failed\n");
			goto error;
		}
	}

	return 0;

error:
	vrdma_free_completion(vrdmaq, i);
	return -ENOMEM;
}

static struct vof_request *vrdma_alloc_req(struct vof_queue *vofq, u16 snd_ndesc, u16 rcv_ndesc)
{
	struct vrdma_queue *vrdmaq = to_vrdmaq(vofq);
	struct ib_device *ibdev = vrdmaq->cm_id->device;
	struct vrdma_request *vrdmareq;
	struct virtio_of_command *vofcmd;
	u64 dma;
	int length;
	u16 ndesc = snd_ndesc + rcv_ndesc;

	/* To reduce kzalloc: combine the request buffer into a single one.
	 * The memory has a layout(vofcmd & descs MUST be continuous):
	 * | vrdmareq     |
	 * | vofcmd       |
	 * | desc * ndesc | (snd desc only, no rcv desc)
	 * | vmem * ndesc |
	 */
	length = sizeof(struct vrdma_request);
	length += sizeof(struct virtio_of_command);
	length += sizeof(struct virtio_of_vring_desc) * ndesc;
	length += sizeof(struct vrdma_mem) * ndesc;
	vrdmareq = kzalloc(length, GFP_KERNEL);
	if (!vrdmareq)
		return NULL;

	vofcmd = (struct virtio_of_command *)(vrdmareq + 1);
	vrdmareq->vofreq.vofcmd = vofcmd;
	if (ndesc) {
		vrdmareq->vofdescs = (struct virtio_of_vring_desc *)(vofcmd + 1);
		vrdmareq->ndesc = ndesc;
		vrdmareq->vmem = (struct vrdma_mem *)(vrdmareq->vofdescs + ndesc);
	}

	length = sizeof(struct virtio_of_command);
	length += sizeof(struct virtio_of_vring_desc) * ndesc;
	dma = ib_dma_map_single(ibdev, vofcmd, length, DMA_TO_DEVICE);
	if (unlikely(ib_dma_mapping_error(ibdev, dma))) {
		dev_err(&vofq->vofdev->vdev.dev, "ib_dma_map_single for command length(%d) failed\n", length);
		goto error;
	}

	ib_dma_sync_single_for_cpu(ibdev, dma, length, DMA_TO_DEVICE);
	vrdmareq->dma = dma;

	return &vrdmareq->vofreq;

error:
	kfree(vrdmareq);
	return NULL;
}

static void vrdma_free_req(struct vof_request *vofreq)
{
	struct vrdma_request *vrdmareq = to_vrdmareq(vofreq);
	struct vrdma_queue *vrdmaq = to_vrdmaq(vofreq->vofq);
	struct ib_device *ibdev = vrdmaq->cm_id->device;
	struct virtio_of_vring_desc *vofdesc;
	struct vrdma_mem *vmem;
	int length;
	u16 idx;

	length = sizeof(struct virtio_of_command);
	length += sizeof(struct virtio_of_vring_desc) * vrdmareq->ndesc;
	ib_dma_unmap_single(ibdev, vrdmareq->dma, length, DMA_TO_DEVICE);

	for (idx = 0; idx < vrdmareq->ndesc; idx++) {
		vmem = vrdmareq->vmem + idx;
		vofdesc = vrdmareq->vofdescs + idx;
		vrdma_mem_dereg(vrdmaq, vmem, le16_to_cpu(vofdesc->flags));
	}

	kfree(vrdmareq);
}

static int vrdma_map_req(struct vof_request *vofreq, u16 idx, struct vring_desc *desc, u16 id, u32 *_length)
{
	struct vrdma_request *vrdmareq = to_vrdmareq(vofreq);
	struct vrdma_queue *vrdmaq = to_vrdmaq(vofreq->vofq);
	struct vof_device *vofdev = vofreq->vofq->vofdev;
	struct virtio_of_vring_desc *vofdesc = vrdmareq->vofdescs + idx;
	struct vrdma_mem *vmem = vrdmareq->vmem + idx;
	void *addr;
	u32 length;
	u16 flags;
	int ret;

	addr = phys_to_virt(virtio64_to_cpu(&vofdev->vdev, desc->addr));
	length = virtio32_to_cpu(&vofdev->vdev, desc->len);
	flags = virtio16_to_cpu(&vofdev->vdev, desc->flags);
	ret = vrdma_mem_reg(vrdmaq, vmem, addr, length, flags);
	if (ret)
		return ret;

	vofdesc->addr = cpu_to_le64(vmem->mr->iova);
	vofdesc->length = cpu_to_le32(length);
	vofdesc->id = cpu_to_le16(id);
	vofdesc->flags = cpu_to_le16(flags);
	vofdesc->key = cpu_to_le32(vmem->mr->rkey);

	return 0;
}

static void vrdma_send_done(struct ib_cq *cq, struct ib_wc *wc)
{
	struct vrdma_request *vrdmareq = container_of(wc->wr_cqe, struct vrdma_request, cqe);

	if (unlikely(wc->status != IB_WC_SUCCESS)) {
	}
}

static int vrdma_queue_req(struct vof_request *vofreq)
{
	struct vrdma_request *vrdmareq = to_vrdmareq(vofreq);
	struct vrdma_queue *vrdmaq = to_vrdmaq(vofreq->vofq);
	struct ib_send_wr wr;
	struct ib_sge sge;
	int ret;

	vrdmareq->cqe.done = vrdma_send_done;

	sge.addr = vrdmareq->dma;
	sge.length = sizeof(struct virtio_of_command) + sizeof(struct virtio_of_vring_desc) * vrdmareq->ndesc;
	sge.lkey = vrdmaq->pd->local_dma_lkey;

	wr.next = NULL;
	wr.wr_cqe = &vrdmareq->cqe;
	wr.sg_list = &sge;
	wr.num_sge = 1;
	wr.opcode = IB_WR_SEND;
	wr.send_flags = IB_SEND_SIGNALED;

	ret = ib_post_send(vrdmaq->cm_id->qp, &wr, NULL);
	if (unlikely(ret)) {
		vof_dev_err(vrdmaq->vofq.vofdev, "ib_post_send error: %d\n", ret);
	}

	return ret;
}

static void vrdma_qp_event(struct ib_event *event, void *context)
{
	pr_debug("QP event %s (%d)\n",
			ib_event_msg(event->event), event->event);

}

static int vrdma_cm_addr_resolved(struct vrdma_queue *vrdmaq)
{
	struct ib_pd *pd = NULL;
	struct ib_cq *cq = NULL;
	struct ib_qp_init_attr init_attr;
	u32 vring_num = vrdmaq->vofq.vring_num;
	int comp_vector = 0;//TODO
	int ret;

	pd = ib_alloc_pd(vrdmaq->cm_id->device, 0);
	if (IS_ERR(pd))
		return PTR_ERR(pd);

	cq = ib_cq_pool_get(vrdmaq->cm_id->device, vring_num, comp_vector, IB_POLL_SOFTIRQ);
	if (IS_ERR(cq)) {
		pr_err("ib_cq_pool_get failed: %d\n", (int)PTR_ERR(cq));
		ret = PTR_ERR(cq);
		goto error;
	}

	memset(&init_attr, 0, sizeof(init_attr));
	init_attr.event_handler = vrdma_qp_event;
	init_attr.cap.max_send_wr = vring_num;
	init_attr.cap.max_recv_wr = vring_num;
	init_attr.cap.max_recv_sge = 1;
	init_attr.cap.max_send_sge = 1;
	init_attr.sq_sig_type = IB_SIGNAL_REQ_WR;
	init_attr.qp_type = IB_QPT_RC;
	init_attr.send_cq = cq;
	init_attr.recv_cq = cq;
	init_attr.qp_context = vrdmaq;
	ret = rdma_create_qp(vrdmaq->cm_id, pd, &init_attr);
	if (ret) {
		pr_err("rdma_create_qp failed: %d\n", ret);
		goto error;
	}

	ret = vrdma_alloc_completion(vrdmaq);
	if (ret)
		goto error;

	ret = rdma_resolve_route(vrdmaq->cm_id, VOF_TIMEOUT);
	if (ret) {
		pr_err("rdma_resolve_route failed: %d\n", ret);
		goto error;
	}

	vrdmaq->pd = pd;
	vrdmaq->cq = cq;

	return 0;

error:
	if (vrdmaq->vrdmacomp)
		vrdma_free_completion(vrdmaq, vring_num);

	if (vrdmaq->cm_id->qp)
		ib_destroy_qp(vrdmaq->cm_id->qp);

	if (pd)
		ib_dealloc_pd(pd);

	if (cq)
		ib_cq_pool_put(cq, vring_num);

	return ret;
}

static int vrdma_cm_route_resolved(struct vrdma_queue *vrdmaq)
{
	struct rdma_conn_param param;
	int ret;

	memset(&param, 0x00, sizeof(struct rdma_conn_param));
	param.qp_num = vrdmaq->cm_id->qp->qp_num;
	param.flow_control = 1;
	param.responder_resources = vrdmaq->cm_id->device->attrs.max_qp_rd_atom;
	param.retry_count = 7;
	param.rnr_retry_count = 7;

	ret = rdma_connect_locked(vrdmaq->cm_id, &param);
	if (ret) {
		pr_err("rdma_connect_locked failed: %d\n", ret);
		return ret;
	}

	return 0;
}

static int vrdma_cm_established(struct vrdma_queue *vrdmaq)
{
	struct vrdma_completion *vrdmacomp;
	int i, ret;

	for (i = 0; i < vrdmaq->vofq.vring_num; i++) {
		vrdmacomp = vrdmaq->vrdmacomp + i;
		ret = vrdma_post_recv(vrdmaq, vrdmacomp);
		if (ret)
			return ret;
	}

	return 0;
}

static int vrdma_cm_handler(struct rdma_cm_id *cm_id, struct rdma_cm_event *ev)
{
	struct vrdma_queue *vrdmaq = cm_id->context;
	int ret;

	pr_debug("event %s, status %d, cm_id %px\n", rdma_event_msg(ev->event), ev->status, cm_id);
	switch (ev->event) {
	case RDMA_CM_EVENT_ADDR_RESOLVED:
		ret = vrdma_cm_addr_resolved(vrdmaq);
		break;
	case RDMA_CM_EVENT_ROUTE_RESOLVED:
		ret = vrdma_cm_route_resolved(vrdmaq);
		break;
	case RDMA_CM_EVENT_ESTABLISHED:
		ret = vrdma_cm_established(vrdmaq);
		vrdmaq->state = ret;
		complete(&vrdmaq->cm_comp);
		break;
	default:
		pr_err("unexpected RDMA CM event (%d)\n", ev->event);
	}
#if 0
	//TODO
	case RDMA_CM_EVENT_REJECTED:
		cm_error = nvme_rdma_conn_rejected(queue, ev);
		break;
	case RDMA_CM_EVENT_ROUTE_ERROR:
	case RDMA_CM_EVENT_CONNECT_ERROR:
	case RDMA_CM_EVENT_UNREACHABLE:
	case RDMA_CM_EVENT_ADDR_ERROR:
		dev_dbg(queue->ctrl->ctrl.device,
				"CM error event %d\n", ev->event);
		cm_error = -ECONNRESET;
		break;
	case RDMA_CM_EVENT_DISCONNECTED:
	case RDMA_CM_EVENT_ADDR_CHANGE:
	case RDMA_CM_EVENT_TIMEWAIT_EXIT:
		dev_dbg(queue->ctrl->ctrl.device,
				"disconnect received - connection closed\n");
		nvme_rdma_error_recovery(queue->ctrl);
		break;
	case RDMA_CM_EVENT_DEVICE_REMOVAL:
		/* device removal is handled via the ib_client API */
		break;
	default:
		dev_err(queue->ctrl->ctrl.device,
				"Unexpected RDMA CM event (%d)\n", ev->event);
		nvme_rdma_error_recovery(queue->ctrl);
		break;
	}
#endif

	if (ret) {
		vrdmaq->state = ret;
		complete(&vrdmaq->cm_comp);
	}

	return 0;
}

static struct vof_queue *vrdma_create_queue(struct vof_device *vofdev, u32 vring_num)
{
	struct vrdma_device *vrdmadev = to_vrdmadev(vofdev);
	struct vrdma_queue *vrdmaq;
	int ret;

	vrdmaq = kzalloc(sizeof(*vrdmaq), GFP_KERNEL);
	if (!vrdmaq)
		return ERR_PTR(-ENOMEM);

	vrdmaq->vofq.vofdev = vofdev;
	vrdmaq->vofq.vring_num = vring_num;
	init_completion(&vrdmaq->cm_comp);
	vrdmaq->state = -ETIMEDOUT;
	vrdmaq->cm_id = rdma_create_id(&init_net, vrdma_cm_handler, vrdmaq, RDMA_PS_TCP, IB_QPT_RC);
	if (IS_ERR(vrdmaq->cm_id)) {
		vof_dev_err(vofdev, "rdma_create_id failed: %d\n", (int)PTR_ERR(vrdmaq->cm_id));
		ret = PTR_ERR(vrdmaq->cm_id);
		goto free_queue;
	}

	ret = rdma_resolve_addr(vrdmaq->cm_id, NULL, (struct sockaddr *)&vrdmadev->taddr, VOF_TIMEOUT);
	if (ret) {
		vof_dev_err(vofdev, "rdma_resolve_addr failed: %d\n", ret);
		goto destroy_cm;
	}

	wait_for_completion_timeout(&vrdmaq->cm_comp, VOF_TIMEOUT);
	if (vrdmaq->state)
		goto destroy_cm;	//TODO free all resources of a queue

	return &vrdmaq->vofq;

destroy_cm:
	rdma_destroy_id(vrdmaq->cm_id);

free_queue:
	kfree(vrdmaq);

	return ERR_PTR(ret);
}

static struct vof_device *vrdma_create(struct vof_options *opts)
{
	struct vrdma_device *vrdmadev;
	int ret;

	vrdmadev = kzalloc(sizeof(*vrdmadev), GFP_KERNEL);
	if (!vrdmadev)
		return ERR_PTR(-ENOMEM);

	ret = inet_pton_with_scope(&init_net, AF_UNSPEC, opts->taddr, opts->tport, &vrdmadev->taddr);
	if (ret) {
		pr_info("invalid target addr & port");
		goto free_dev;
	}

	if (opts->iaddr) {
		ret = inet_pton_with_scope(&init_net, AF_UNSPEC, opts->iaddr, opts->iport, &vrdmadev->iaddr);
		if (ret) {
			pr_info("invalid initiator addr & port");
			goto free_dev;
		}
	}

	vrdmadev->vofdev.opts = opts;
	return &vrdmadev->vofdev;

free_dev:
	kfree(vrdmadev);
	return ERR_PTR(ret);
}

static void vrdma_destroy(struct vof_device *vofdev)
{
	struct vrdma_device *vrdmadev = to_vrdmadev(vofdev);

	kfree(vrdmadev);
}

static struct vof_transport_ops vrdma_transport_ops = {
	.transport = "rdma",
	.oftype = virtio_of_connection_rdma,
	.module = THIS_MODULE,
	.create = vrdma_create,
	.destroy = vrdma_destroy,
	.create_queue = vrdma_create_queue,
	.alloc_req = vrdma_alloc_req,
	.free_req = vrdma_free_req,
	.queue_req = vrdma_queue_req,
	.map_req = vrdma_map_req,
};

static int __init vrdma_init(void)
{
	vof_register_transport(&vrdma_transport_ops);
	return 0;
}

static void __exit vrdma_exit(void)
{
	vof_unregister_transport(&vrdma_transport_ops);
}

module_init(vrdma_init);
module_exit(vrdma_exit);

MODULE_AUTHOR(VRDMA_MODULE_AUTHOR);
MODULE_DESCRIPTION(VRDMA_MODULE_DESC);
MODULE_LICENSE(VRDMA_MODULE_LICENSE);
MODULE_VERSION(VRDMA_MODULE_VERSION);
