/* Created by shyang */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/linkage.h>
#include <linux/types.h>
#include <linux/list.h>
#include <net/puzzle.h>
#include <crypto/hash.h>

LIST_HEAD(policy_head);
LIST_HEAD(cache_head);

static u32 puzzle_type = PZLTYPE_NONE;
static bool addlock = false;

static struct puzzel_dns_info {
    u32 ip;
    u32 port;
} puzzle_dns = {0, 0};

/* Puzzle functions: hash, solve, check puzzles */

u32 do_hash_puzzle(__u32 nonce, __u32 seed, __u32 dns_ip, __u32 client_ip, __u32 puzzle_type) {
    unsigned char plaintext[PLAIN_LENGTH];
    unsigned char hash_sha256[SHA256_LENGTH];
    struct crypto_shash *sha256;
    struct shash_desc *shash;
    __u32 size, result, offset, temp;
    __u32 i, j = 0;
    for(i = 0; i < 4; ++i, ++j) {
        plaintext[j] = nonce & 255;
        nonce >>= 8;
    }
    for(i = 0; i < 4; ++i, ++j) {
        plaintext[j] = seed & 255;
        seed >>= 8;
    }
    for(i = 0; i < 4; ++i, ++j) {
        plaintext[j] = dns_ip & 255;
        dns_ip >>= 8;
    }
    for(i = 0; i < 4; ++i, ++j) {
        plaintext[j] = client_ip & 255;
        client_ip >>= 8;
    }
    for(i = 0; i < 1; ++i, ++j) {
        plaintext[j] = puzzle_type & 255;
        puzzle_type >>= 8;
    }
    sha256 = crypto_alloc_shash("sha256", 0, 0);
    size = sizeof(struct shash_desc) + crypto_shash_descsize(sha256);
    shash = kmalloc(size, GFP_KERNEL);
    
    if(sha256 == NULL) {
        return 0;
    }
    shash->tfm = sha256;
    
    crypto_shash_init(shash);
    crypto_shash_update(shash, plaintext, PLAIN_LENGTH);
    crypto_shash_final(shash, hash_sha256);
    crypto_free_shash(sha256);
    kfree(shash);
    result = 0;
    for(i = 0; i < 4; ++i) {
        result = result << 8;
        temp = 0;
        offset = i << 3;
        for(j = 0; j < 8; ++j) {
            temp = temp ^ hash_sha256[offset + j];
        }
        result = result + temp;
    }
    return result;
}
SYSCALL_DEFINE5(hash_puzzle, __u32, nonce, __u32, puzzle, __u32, dns_ip, __u32, client_ip, __u32, puzzle_type) {
    return do_hash_puzzle(nonce, puzzle, dns_ip, client_ip, puzzle_type);
}

u32 do_solve_puzzle(__u32 threshold, __u32 puzzle, __u32 dns_ip, __u32 client_ip, __u32 puzzle_type) {
    __u32 nonce;
    for(nonce = 1; nonce > 0; ++nonce) {
        if(do_hash_puzzle(nonce, puzzle, dns_ip, client_ip, puzzle_type) < threshold) {
            return nonce;
        }
    }
    return 0;
}
EXPORT_SYMBOL(do_solve_puzzle);
SYSCALL_DEFINE5(solve_puzzle, __u32, threshold, __u32, puzzle, __u32, dns_ip, __u32, client_ip, __u32, puzzle_type) {
    return do_solve_puzzle(threshold, puzzle, dns_ip, client_ip, puzzle_type);
}

int do_check_puzzle(u32 type, u32 puzzle, u32 dns_ip, u32 nonce, u32 threshold, u32 client_ip) {
    struct puzzle_policy* policy;
    if (find_puzzle_policy(dns_ip, &policy) != 0) return 1;
    printk(KERN_INFO "dns ip : %u, puzzle : %u, nonce : %u, threshold : %u / pthreshold : %u", dns_ip, puzzle, nonce, threshold, policy->threshold);
    printk(KERN_INFO "host pt %u / client pt %u", puzzle_type, type);
    if (puzzle_type == PZLTYPE_NONE)
        return 0; // don't need to solve puzzle -> valid
    if (type == PZLTYPE_NONE)
        return 1; // wrong puzzle type -> invalid
    if (threshold != policy->threshold)
        return 1; // wrong threshold -> cheating about ISP -> invalid
    if (delete_cbf(policy, puzzle) == 0) 
        return 1; // invalid puzzle check using CBF -> invalid
    if (do_hash_puzzle(nonce, puzzle, dns_ip, client_ip, puzzle_type) < policy->threshold)
       return 0; // correct solve puzzle -> valid
    return 1; // else -> invalid
}
EXPORT_SYMBOL(do_check_puzzle);
SYSCALL_DEFINE6(check_puzzle, __u32, type, __u32, puzzle, __u32, dns_ip, __u32, nonce, __u32, threshold, __u32, policy_ip)
{
    return do_check_puzzle(type, puzzle, dns_ip, nonce, threshold, policy_ip);
}

/* Puzzle policy functions: control each ISP for server */

int find_puzzle_policy(u32 ip, struct puzzle_policy** ptr) {
    struct puzzle_policy* policy;
    struct list_head* head;
    switch(puzzle_type) {
    case PZLTYPE_EXT:
        list_for_each(head, &policy_head) {
            policy = list_entry(head, struct puzzle_policy, list);
            if (ip == policy->ip) {
                *ptr = policy;
                return 0;
            }
        }
        return 1;
    default:
        return 1;
    }
}
EXPORT_SYMBOL(find_puzzle_policy);

long add_puzzle_policy(u32 ip, struct puzzle_policy** ptr) {
    struct puzzle_policy* policy;
    if (addlock) return -1;
    addlock = true;
    
    policy = kmalloc(sizeof(*policy), GFP_KERNEL);
    memset(policy, 0, sizeof(*policy));

    policy->ip = ip;
    *ptr = policy;

    list_add_tail(&(policy->list), &policy_head);

    addlock = false;

    return 0;
}
EXPORT_SYMBOL(add_puzzle_policy);

long update_puzzle_policy(u32 ip, u32 seed, u32 length, u32 threshold) {
    struct puzzle_policy* policy;
    if (find_puzzle_policy(ip, &policy) != 0) {
        add_puzzle_policy(ip, &policy);
    }

    policy->seed = seed;
    policy->length = length;
    policy->threshold = threshold;

    u32 token = seed;
    for (int j = 0; j < policy->length; ++j) {
        insert_cbf(policy, token);
        token = hash_cbf(HASH_SALT, token);
    }
    return 0;
}
EXPORT_SYMBOL(update_puzzle_policy);
SYSCALL_DEFINE4(set_puzzle_policy, __u32, ip, __u32, seed, __u32, length, __u32, threshold)
{
    return update_puzzle_policy(ip, seed, length, threshold);
}

long print_puzzle_policy(u32 ip) {
    struct puzzle_policy* policy;
    if (puzzle_type == PZLTYPE_NONE) {
        printk("don't use puzzle policy\n");
        return 0;
    }
    printk(KERN_INFO "-puzzle_policy---type:%u-\n", puzzle_type);

    if (find_puzzle_policy(ip, &policy) == 0) {
        u32 dip = ntohl(policy->ip);
        printk(KERN_INFO "ip : %u.%u.%u.%u (%u)", (dip>>24)%256, (dip>16)%256, (dip>>8)%256, dip%256, policy->ip);
        printk(KERN_INFO "seed : %u, length : %u\n", policy->seed, policy->length);
        printk(KERN_INFO "threshold : %u\n", policy->threshold);
    }
    else printk(KERN_INFO "invalid dns ip\n");
    printk(KERN_INFO "-------------------------\n");
    return 0;
}
SYSCALL_DEFINE1(get_puzzle_policy, __u32, ip)
{
    return print_puzzle_policy(ip);
}

int clear_puzzle_policy(void) {
    struct puzzle_policy* policy;

    addlock = true;
    while (!list_empty(&policy_head)) {
        policy = list_first_entry(&policy_head, struct puzzle_policy, list);
        list_del(&(policy->list));
        kfree(policy);
    }
    addlock = false;

    return 0;
}

/* Puzzle cache functions: save and load puzzle for clients */

int find_puzzle_cache(u32 ip, struct puzzle_cache** ptr) {
    struct puzzle_cache* cache;
    struct list_head* head;
    list_for_each(head, &cache_head) {
        cache = list_entry(head, struct puzzle_cache, list);
        if (ip == cache->ip) {
            *ptr = cache;
            return 0;
        }
    }
    return 1;
}
EXPORT_SYMBOL(find_puzzle_cache);

int update_puzzle_cache(u32 ip, u32 dns_ip, u32 type, u32 puzzle, u32 threshold) {
    struct puzzle_cache* cache;
    int updated = 0;

    if(find_puzzle_cache(ip, &cache) != 0) {
        if(type == PZLTYPE_NONE) return 0;

        cache = kmalloc(sizeof(*cache), GFP_KERNEL);
        memset(cache, 0, sizeof(*cache));

        cache->ip = ip;
        cache->dns_ip = dns_ip;
        cache->puzzle_type = type;
        cache->puzzle = puzzle;
        cache->threshold = threshold;
        printk("new ip:%u dns ip:%u type:%u puzzle:%u threshold:%u\n", 
            cache->ip, cache->dns_ip, cache->puzzle_type, cache->puzzle, cache->threshold);

        list_add_tail(&(cache->list), &cache_head);
        return 4;
    }

    if(type) {
        if(type == PZLTYPE_NONE) {
            list_del(&(cache->list));
            kfree(cache);
            return 4;
        }
	    if(type != cache->puzzle_type) cache->puzzle = 0;
        cache->puzzle_type = type;
    }

    if(puzzle && cache->puzzle != puzzle) {
        updated++;
        cache->puzzle = puzzle;
    }
    if(threshold && cache->threshold != threshold) {
        updated++;
        cache->threshold = threshold;
    }

    printk("modified ip:%u dns ip:%u type:%u puzzle:%u threshold:%u\n", 
        cache->ip, cache->dns_ip, cache->puzzle_type, cache->puzzle, cache->threshold);

    return updated;
}
EXPORT_SYMBOL(update_puzzle_cache);
SYSCALL_DEFINE5(set_puzzle_cache, __u32, ip, __u32, dns_ip, __u32, type, __u32, puzzle, __u32, threshold)
{
    return update_puzzle_cache(ip, dns_ip, type, puzzle, threshold);
}

long print_puzzle_cache(u32 ip) {
    struct puzzle_cache* cache;
    printk(KERN_INFO "--puzzle_cache-----\n");
    if (find_puzzle_cache(ip, &cache) == 0) {
        u32 cip = ntohl(cache->ip);
        u32 dip = ntohl(cache->dns_ip);
        printk(KERN_INFO "ip : %u.%u.%u.%u (%u)", (cip>>24)%256, (cip>16)%256, (cip>>8)%256, cip%256, cache->ip);
        printk(KERN_INFO "dns ip : %u.%u.%u.%u (%u)", (dip>>24)%256, (dip>16)%256, (dip>>8)%256, dip%256, cache->dns_ip);
        printk(KERN_INFO "puzzle type : %u, puzzle : %u\n", cache->puzzle_type, cache->puzzle);
        printk(KERN_INFO "threshold : %u\n", cache->threshold);
    }
    else printk(KERN_INFO "invalid client ip\n");
    printk(KERN_INFO "-------------------\n");
    return 0;
}

SYSCALL_DEFINE1(get_puzzle_cache, __u32, ip)
{
    return print_puzzle_cache(ip);
}

/* General syscalls */

long do_get_threshold(u32 ip) {
	struct puzzle_policy* policy;
	if (find_puzzle_policy(ip, &policy) != 0) return 0;
	return policy->threshold;
}
SYSCALL_DEFINE1(get_threshold, __u32, ip) {
	return do_get_threshold(ip);
}

u32 do_set_threshold(u32 ip, u32 threshold) {
	struct puzzle_policy* policy;
	if (find_puzzle_policy(ip, &policy) == 0) return policy->threshold = threshold;
    else add_policy(ip, threshold);
	return threshold;
}
EXPORT_SYMBOL(do_set_threshold);
SYSCALL_DEFINE2(set_threshold, __u32, ip, __u32, threshold) {
	return do_set_threshold(ip, threshold);
}

u32 do_get_puzzle_type() {
    return puzzle_type;
}
EXPORT_SYMBOL(do_get_puzzle_type);
SYSCALL_DEFINE0(get_puzzle_type) {
    return do_get_puzzle_type();
}
u32 do_set_puzzle_type(u32 type) {
    if (type != PZLTYPE_NONE) {
        clear_puzzle_policy();
    }
    puzzle_type = type;
    return puzzle_type;
}
EXPORT_SYMBOL(do_set_puzzle_type);
SYSCALL_DEFINE1(set_puzzle_type, __u32, type) {
    return do_set_puzzle_type(type);
}

long do_get_local_dns() {
    return puzzle_dns.ip;
}
EXPORT_SYMBOL(do_get_local_dns);
SYSCALL_DEFINE0(get_local_dns) {
    return do_get_local_dns();
}

long do_set_local_dns(u32 ip, u32 port) {
    puzzle_dns.ip = ip;
    puzzle_dns.port = port;
    return 0;
}
EXPORT_SYMBOL(do_set_local_dns);
SYSCALL_DEFINE2(set_local_dns, __u32, ip, __u32, port) {
    return do_set_local_dns(ip, port);
}

/* CBF(Counting Bloom Filter) functions */

u32 hash_cbf(u32 salt, u32 x) {
    unsigned char input[CBF_INPUT_LENGTH];
    unsigned char hash_sha256[SHA256_LENGTH];
    struct crypto_shash *sha256;
    struct shash_desc *shash;
    __u32 size, result, offset, temp;
    __u32 i, j = 0;
    for(i = 0; i < 4; ++i, ++j) {
        input[j] = salt & 255;
        salt >>= 8;
    }
    for(i = 0; i < 4; ++i, ++j) {
        input[j] = x & 255;
        x >>= 8;
    }
    sha256 = crypto_alloc_shash("sha256", 0, 0);
    size = sizeof(struct shash_desc) + crypto_shash_descsize(sha256);
    shash = kmalloc(size, GFP_KERNEL);
    
    if(sha256 == NULL) {
        return 0;
    }
    shash->tfm = sha256;
    
    crypto_shash_init(shash);
    crypto_shash_update(shash, input, CBF_INPUT_LENGTH);
    crypto_shash_final(shash, hash_sha256);
    crypto_free_shash(sha256);
    kfree(shash);
    result = 0;
    for(i = 0; i < 4; ++i) {
        result = result << 8;
        temp = 0;
        offset = i << 3;
        for(j = 0; j < 8; ++j) {
            temp = temp ^ hash_sha256[offset + j];
        }
        result = result + temp;
    }
    return result;
}

int insert_cbf(struct puzzle_policy* policy, u32 x) {
    for (int i = 0; i < HASH_FUNCTIONS; ++i) {
        u32 p = hash_cbf(i, x) % BUCKET_SIZE;
        ++(policy -> table)[p];
    }
    return 0;
}

int check_cbf(struct puzzle_policy* policy, u32 x) {
    for (int i = 0; i < HASH_FUNCTIONS; ++i) {
        u32 p = hash_cbf(i, x) % BUCKET_SIZE;
        if ((policy -> table)[p] <= 0) return 0;
    }
    return 1;
}

int delete_cbf(struct puzzle_policy* policy, u32 x) {
    if (!check_cbf(policy, x)) return 0;
    for (int i = 0; i < HASH_FUNCTIONS; ++i) {
        u32 p = hash_cbf(i, x) % BUCKET_SIZE;
        --(policy -> table)[p];
    }
    return 1;
}
