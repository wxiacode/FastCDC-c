# FastCDC-c
An implementation of FastCDC in C

FastCDC is an advanced chunking algorithm which has a better speed than Rabin CDC.

When enable GCC O3 Flag, it can achieve 4.448 GB/s in some datasets.

An open-source paper is [there](https://www.usenix.org/conference/atc16/technical-sessions/presentation/xia)

Related Paper:

* Wen Xia, Yukun Zhou, Hong Jiang, Dan Feng, Yu Hua, Yuchong Hu, Yucheng Zhang, Qing Liu, "FastCDC: a Fast and Efficient Content-Defined Chunking Approach for Data Deduplication", in Proceedings of USENIX Annual Technical Conference (USENIX ATC'16), Denver, CO, USA, June 22–24, 2016, pages: 101-114. [LINK](https://www.usenix.org/conference/atc16/technical-sessions/presentation/xia)

* Wen Xia, Xiangyu Zou, Yukun Zhou, Hong Jiang, Chuanyi Liu, Dan Feng, Yu Hua, Yuchong Hu, Yucheng Zhang, "The Design of Fast Content-Defined Chunking for Data Deduplication based Storage Systems", IEEE Transactions on Parallel and Distributed Systems (TPDS), 2020. [LINK](https://ieeexplore.ieee.org/document/9055082)

Commercial use is welcome, but please let us know by email (xiawen@hit.edu.cn) and report any problems you encounter.


### Dependency
* openssl
* zlib
* uthash
