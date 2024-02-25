# PDTC-kernel
Raspberry pi linux kernel source code of 'Puzzle-centric DDoS Traffic Control: A DNS-based Approach'

## Important syscalls

| num | name | input | output |
|:-----:|:-------------:|:-----------:|:-----------:|
| 454 | get_puzzle_policy | u32 ip | print puzzle policy in kernel |
| 455 | set_puzzle_policy | u32 ip, u32 seed, u32 length, u32 threshold | |
| 456 | get_puzzle_cache | u32 ip | print puzzle cache in kernel |
| 457 | set_puzzle_cache | u32 ip, u32 dns ip u32 type, u32 puzzle, u32 threshold | |
| 458 | get_threshold | u32 ip | return threshold corresponding ISP |
| 459 | set_threshold | u32 ip, u32 threshold |
| 460 | get_puzzle_type | | return puzzle type |
| 461 | set_puzzle_type | u32 type | |

### syscall#454(get_puzzle_policy)

### syscall#455(set_puzzle_policy)

### syscall#456(get_puzzle_cache)

### syscall#457(set_puzzle_cache)

### syscall#458(get_threshold)

### syscall#459(set_threshold)

### syscall#460(get_puzzle_type)

### syscall#461(set_puzzle_type)