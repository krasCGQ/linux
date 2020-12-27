#define ALT_SCHED_VERSION_MSG "sched/bmq: BMQ CPU Scheduler "ALT_SCHED_VERSION" by Alfred Chen.\n"

/*
 * BMQ only routines
 */
#define rq_switch_time(rq)	((rq)->clock - (rq)->last_ts_switch)
#define boost_threshold(p)	(sched_timeslice_ns >>\
				 (15 - MAX_PRIORITY_ADJ -  (p)->boost_prio))

static inline void boost_task(struct task_struct *p)
{
	int limit;

	switch (p->policy) {
	case SCHED_NORMAL:
		limit = -MAX_PRIORITY_ADJ;
		break;
	case SCHED_BATCH:
	case SCHED_IDLE:
		limit = 0;
		break;
	default:
		return;
	}

	if (p->boost_prio > limit)
		p->boost_prio--;
}

static inline void deboost_task(struct task_struct *p)
{
	if (p->boost_prio < MAX_PRIORITY_ADJ)
		p->boost_prio++;
}

/*
 * Common interfaces
 */
static inline int normal_prio(struct task_struct *p)
{
	if (task_has_rt_policy(p))
		return MAX_RT_PRIO - 1 - p->rt_priority;

	return p->static_prio + MAX_PRIORITY_ADJ;
}

static inline int task_sched_prio(struct task_struct *p, struct rq *rq)
{
	return (p->prio < MAX_RT_PRIO)? p->prio : MAX_RT_PRIO / 2 + (p->prio + p->boost_prio) / 2;
}

static inline void requeue_task(struct task_struct *p, struct rq *rq);

static inline void time_slice_expired(struct task_struct *p, struct rq *rq)
{
	p->time_slice = sched_timeslice_ns;

	if (SCHED_FIFO != p->policy && task_on_rq_queued(p)) {
		if (SCHED_RR != p->policy)
			deboost_task(p);
		requeue_task(p, rq);
	}
}

inline int task_running_nice(struct task_struct *p)
{
	return (p->prio + p->boost_prio > DEFAULT_PRIO + MAX_PRIORITY_ADJ);
}

static inline void update_task_priodl(struct task_struct *p) {}

static inline unsigned long sched_queue_watermark(struct rq *rq)
{
	return find_first_bit(rq->queue.bitmap, SCHED_BITS);
}

static inline void sched_queue_init(struct rq *rq)
{
	struct bmq *q = &rq->queue;
	int i;

	bitmap_zero(q->bitmap, SCHED_BITS);
	for(i = 0; i < SCHED_BITS; i++)
		INIT_LIST_HEAD(&q->heads[i]);
}

static inline void sched_queue_init_idle(struct rq *rq, struct task_struct *idle)
{
	struct bmq *q = &rq->queue;

	idle->bmq_idx = IDLE_TASK_SCHED_PRIO;
	INIT_LIST_HEAD(&q->heads[idle->bmq_idx]);
	list_add(&idle->bmq_node, &q->heads[idle->bmq_idx]);
	set_bit(idle->bmq_idx, q->bitmap);
}

/*
 * This routine used in bmq scheduler only which assume the idle task in the bmq
 */
static inline struct task_struct *sched_rq_first_task(struct rq *rq)
{
	unsigned long idx = find_first_bit(rq->queue.bitmap, SCHED_BITS);
	const struct list_head *head = &rq->queue.heads[idx];

	return list_first_entry(head, struct task_struct, bmq_node);
}

static inline struct task_struct *
sched_rq_next_task(struct task_struct *p, struct rq *rq)
{
	unsigned long idx = p->bmq_idx;
	struct list_head *head = &rq->queue.heads[idx];

	if (list_is_last(&p->bmq_node, head)) {
		idx = find_next_bit(rq->queue.bitmap, SCHED_BITS, idx + 1);
		head = &rq->queue.heads[idx];

		return list_first_entry(head, struct task_struct, bmq_node);
	}

	return list_next_entry(p, bmq_node);
}

#define __SCHED_DEQUEUE_TASK(p, rq, flags, func)	\
	psi_dequeue(p, flags & DEQUEUE_SLEEP);		\
	sched_info_dequeued(rq, p);			\
							\
	list_del(&p->bmq_node);				\
	if (list_empty(&rq->queue.heads[p->bmq_idx])) {	\
		clear_bit(p->bmq_idx, rq->queue.bitmap);\
		func;					\
	}

#define __SCHED_ENQUEUE_TASK(p, rq, flags)				\
	sched_info_queued(rq, p);					\
	psi_enqueue(p, flags);						\
									\
	p->bmq_idx = task_sched_prio(p, rq);				\
	list_add_tail(&p->bmq_node, &rq->queue.heads[p->bmq_idx]);	\
	set_bit(p->bmq_idx, rq->queue.bitmap)

#define __SCHED_REQUEUE_TASK(p, rq, func)				\
{									\
	int idx = task_sched_prio(p, rq);				\
\
	list_del(&p->bmq_node);						\
	list_add_tail(&p->bmq_node, &rq->queue.heads[idx]);		\
	if (idx != p->bmq_idx) {					\
		if (list_empty(&rq->queue.heads[p->bmq_idx]))		\
			clear_bit(p->bmq_idx, rq->queue.bitmap);	\
		p->bmq_idx = idx;					\
		set_bit(p->bmq_idx, rq->queue.bitmap);			\
		func;							\
	}								\
}

static inline bool sched_task_need_requeue(struct task_struct *p, struct rq *rq)
{
	return (task_sched_prio(p, rq) != p->bmq_idx);
}

static void sched_task_fork(struct task_struct *p, struct rq *rq)
{
	p->boost_prio = (p->boost_prio < 0) ?
		p->boost_prio + MAX_PRIORITY_ADJ : MAX_PRIORITY_ADJ;
}

/**
 * task_prio - return the priority value of a given task.
 * @p: the task in question.
 *
 * Return: The priority value as seen by users in /proc.
 * RT tasks are offset by -100. Normal tasks are centered around 1, value goes
 * from 0(SCHED_ISO) up to 82 (nice +19 SCHED_IDLE).
 */
int task_prio(const struct task_struct *p)
{
	if (p->prio < MAX_RT_PRIO)
		return (p->prio - MAX_RT_PRIO);
	return (p->prio - MAX_RT_PRIO + p->boost_prio);
}

static void do_sched_yield_type_1(struct task_struct *p, struct rq *rq)
{
	p->boost_prio = MAX_PRIORITY_ADJ;
}

#ifdef CONFIG_SMP
static void sched_task_ttwu(struct task_struct *p)
{
	if(this_rq()->clock_task - p->last_ran > sched_timeslice_ns)
		boost_task(p);
}
#endif

static void sched_task_deactivate(struct task_struct *p, struct rq *rq)
{
	if (rq_switch_time(rq) < boost_threshold(p))
		boost_task(p);
}
