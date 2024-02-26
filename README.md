# PDTC-kernel
Raspberry pi linux kernel source code of 'Puzzle-centric DDoS Traffic Control: A DNS-based Approach'

## Important syscalls

| num | name | input (value type: u32) | output |
|:-----:|:-------------|:-----------|:-----------|
| 454 | get_puzzle_policy | ip | print puzzle policy in kernel |
| 455 | set_puzzle_policy | ip, seed, length, threshold | |
| 456 | get_puzzle_cache | ip | print puzzle cache in kernel |
| 457 | set_puzzle_cache | ip, dns ip, type, puzzle, threshold | |
| 458 | get_threshold | ip | return threshold corresponding ISP |
| 459 | set_threshold | ip, threshold |
| 460 | get_puzzle_type | | return puzzle type |
| 461 | set_puzzle_type | type | |
