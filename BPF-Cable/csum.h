#include <linux/if_ether.h>

typedef __u32 __wsum;

static __always_inline __sum16 csum_fold(__wsum csum)
{
	csum = (csum & 0xffff) + (csum >> 16);
	csum = (csum & 0xffff) + (csum >> 16);
	return (__sum16)~csum;
}

static __always_inline __wsum csum_unfold(__sum16 csum)
{
	return (__wsum)csum;
}

static __always_inline __wsum csum_add(__wsum csum, __wsum addend)
{
	csum += addend;
	return csum + (csum < addend);
}

static __always_inline  void
__csum_replace_by_diff(__sum16 *sum, __wsum diff)
{
	*sum = csum_fold(csum_add(diff, ~csum_unfold(*sum)));
}

static __always_inline  void
__csum_replace_by_4(__sum16 *sum, __wsum from, __wsum to)
{
	__csum_replace_by_diff(sum, csum_add(~from, to));
}

static __always_inline  int
l4_csum_replace(const struct xdp_md *ctx, __u64 off, __u32 from, __u32 to,
		__u32 flags)
{
	bool is_mmzero = flags & BPF_F_MARK_MANGLED_0;
	__u32 size = flags & BPF_F_HDR_FIELD_MASK;
	__sum16 *sum;
	int ret;

	if (unlikely(flags & ~(BPF_F_MARK_MANGLED_0 | BPF_F_PSEUDO_HDR |
			       BPF_F_HDR_FIELD_MASK)))
		return -EINVAL;
	if (unlikely(size != 0 && size != 2))
		return -EINVAL;
	/* See xdp_load_bytes(). */
	asm volatile("r1 = *(u32 *)(%[ctx] +0)\n\t"
		     "r2 = *(u32 *)(%[ctx] +4)\n\t"
		     "%[off] &= %[offmax]\n\t"
		     "r1 += %[off]\n\t"
		     "%[sum] = r1\n\t"
		     "r1 += 2\n\t"
		     "if r1 > r2 goto +2\n\t"
		     "%[ret] = 0\n\t"
		     "goto +1\n\t"
		     "%[ret] = %[errno]\n\t"
		     : [ret]"=r"(ret), [sum]"=r"(sum)
		     : [ctx]"r"(ctx), [off]"r"(off),
		       [offmax]"i"(__CTX_OFF_MAX), [errno]"i"(-EINVAL)
		     : "r1", "r2");
	if (!ret) {
		if (is_mmzero && !*sum)
			return 0;
		from ? __csum_replace_by_4(sum, from, to) :
		       __csum_replace_by_diff(sum, to);
		if (is_mmzero && !*sum)
			*sum = CSUM_MANGLED_0;
	}
	return ret;
}