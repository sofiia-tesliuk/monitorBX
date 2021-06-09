#ifndef THESIS_BPF_BPF_INCLUDES_H
#define THESIS_BPF_BPF_INCLUDES_H

#define BPF_ANY       0 /* create new element or update existing */
#define BPF_NOEXIST   1 /* create new element only if it didn't exist */
#define m 128
#define p_bits 7
#define q_bits (32 - p_bits)
#define estimation_coef (0.7213 / ( 1.+1.079/m)*m*m ) // a_m * m^2
#define pow_2_32 4294967296
#define k_neighbors 7

#define SLEEP_SECONDS 5

typedef unsigned int u32;

#endif //THESIS_BPF_BPF_INCLUDES_H
