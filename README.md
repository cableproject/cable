Cable is a framework to accelerate and schedule 5G UPF based on eBPF. It accelerates packets processing time for UPF by bypassing the Linux kernel based on XDP/eBPF. It also monitors the state of UPF by eBPF and then schedules PDU sesion to other UPFs if the UPF is overloaded. We implement Cable in Free5GC (v3.0.5, https://github.com/free5gc/free5gc/tree/v3.0.5) and Ubuntu 18.04 (kernel 5.4).

The source code of Cable consists two parts. One is the Free5GC-Cable. We have modified the Free5GC's NFs (mainly in SMF and UPF) to achieve UPF monitoring. The SMF and UPF use N4 interface to communicate with each other and the N4 interface is based on pfcp, so you need to put the pfcp@v1.0.0 (already in the Free5GC-Cable directory) GO lib into your GO path. The steps of compiling and running Free5GC-Cable is the same with original Free5GC.

The other part of Cable is BPF-Cable. The BPF-Cable consists of the packet QoS processing in kernel, packet kernel bypassing and UPF kernel monitor. To use BPF-Cable you need to follow the steps:

1 Download the Linux 5.4 kernel source code form https://github.com/torvalds/linux/tree/v5.4

2 Put the code in BPF-Cable to the kernel source code:

```sh
cp ./BPF-Cable/*  ./linux/samples/bpf
```

3 Enter the linux code directory:

```sh
cd ./linux/
```

4 Compile:

```sh
make M=samples/bpf
```

5 Load and Run

5.1 Load the tc and QoS:

```sh
tc  filter add dev ens1f1 egress bpf da obj qos_kern.o sec qos verbose
```

5.2 Check the index of the ens1f1:

```sh
ip link | grep ens1f1
```

5.3 If the index is 4, then run:

```sh
./qos -i 4
```


