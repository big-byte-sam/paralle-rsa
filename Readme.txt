Pres-run:
==========
1- Make sure to compile the "samer_rsa_mpi.c" using mpi first
2- Compile and run "samer_rsa.c"



Method Options:
===============
1- Sequential: runs the sequential algorithm allowing to input your own public and private keys, and n
2- MPI: runs the MPI paradigm allowing to input your own public and private keys, and n
3- Multithreading: runs the PThread paradigm allowing to input your own public and private keys, and n
4- Compare all: runs all the algorithm using the same public and private keys for all algorithms and calculating the execution time for each step




NOTEs: 
- When running the mpi code by selecting option 2, some printing messages are cropped
- A choice of 16-bit length key will generate a 1- digit public and private keys