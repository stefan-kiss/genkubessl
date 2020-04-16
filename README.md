[![Build Status](https://travis-ci.com/stefan-kiss/genkubessl.svg?branch=master)](https://travis-ci.com/stefan-kiss/genkubessl)
[![go-report](https://goreportcard.com/badge/github.com/stefan-kiss/genkubessl)](https://goreportcard.com/report/github.com/stefan-kiss/genkubessl) 
# genkubessl

A tool for generating and managing kubernetes ssl certificates.

# Motivation
* manage most certificate operations in a kubernetes cluster
* learning project
    * this is my first GOlang project
    * it also helps me better understand kubernetes internals as well as kubeadm internals
    * should also be able to provide a better overview of certificate creation and management in kubernetes
* should allow for more flexibility than kubeadm
* defaults should provide both a sane and usable setup

# Typical usage

The typical usage is as follows:
    
    * data about the kubernetes nodesand services is transmitted via command line
    * the program generates the certificates and stores them in an directory structure on a given storage medium
    * it is then the user's responsability to distribute the certificates to the nodes
    * in a future version there will be a 'local' option allowing the execution directly on the target node 

See below for example output structure.
# Project structure

```text
https://github.com/golang-standards/project-layout
```


### Copyright

This project is licensed under APACHE 2.0 license.
Please see the included LICENSE file.

This project contains code copied or inspired from the following projects: 

```text
https://github.com/kubernetes/
https://golang.org/
```

### Examples

```bash
./genkubessl kubecerts -basepath outputs/kubernetes.example.com/system \
    -apisans kapi.kubernetes.example.com/10.0.0.1 \
    -masters master001.local.kubernetes.example.com/10.10.1.70,master002.local.kubernetes.example.com/10.10.1.85 \
    -workers worker001.local.kubernetes.example.com/10.10.1.207,worker002.local.kubernetes.example.com/10.10.1.104,worker003.local.kubernetes.example.com/10.10.1.139 \
    -etcd master001.local.kubernetes.example.com/10.10.1.70,master002.local.kubernetes.example.com/10.10.1.85 \
    -users stefan.kiss/admin
```
Given that input it will write the following file structure

```
└── outputs
    └── kubernetes.example.com
        └── system
            ├── global
            │   └── etc
            │       └── kubernetes
            │           └── pki
            │               ├── admin.crt
            │               ├── admin.key
            │               ├── ca.crt
            │               ├── ca.key
            │               ├── etcd
            │               │   ├── ca.crt
            │               │   └── ca.key
            │               ├── front-proxy-ca.crt
            │               ├── front-proxy-ca.key
            │               ├── sa.key
            │               ├── sa.pub
            │               └── users
            │                   ├── stefan.kiss.crt
            │                   └── stefan.kiss.key
            └── nodes
                ├── master001.local.kubernetes.example.com
                │   ├── etc
                │   │   └── kubernetes
                │   │       └── pki
                │   │           ├── apiserver-etcd-client.crt
                │   │           ├── apiserver-etcd-client.key
                │   │           ├── apiserver-kubelet-client.crt
                │   │           ├── apiserver-kubelet-client.key
                │   │           ├── apiserver.crt
                │   │           ├── apiserver.key
                │   │           ├── controller-manager.crt
                │   │           ├── controller-manager.key
                │   │           ├── etcd
                │   │           │   ├── etcd-healthcheck-client.crt
                │   │           │   ├── etcd-healthcheck-client.key
                │   │           │   ├── peer.crt
                │   │           │   ├── peer.key
                │   │           │   ├── server.crt
                │   │           │   └── server.key
                │   │           ├── front-proxy-client.crt
                │   │           ├── front-proxy-client.key
                │   │           ├── kube-proxy.crt
                │   │           ├── kube-proxy.key
                │   │           ├── kubelet.crt
                │   │           ├── kubelet.key
                │   │           ├── scheduler.crt
                │   │           └── scheduler.key
                │   └── var
                │       └── lib
                │           └── kubelet
                │               └── pki
                │                   ├── kubelet.crt
                │                   └── kubelet.key
                ├── master002.local.kubernetes.example.com
                │   ├── etc
                │   │   └── kubernetes
                │   │       └── pki
                │   │           ├── apiserver-etcd-client.crt
                │   │           ├── apiserver-etcd-client.key
                │   │           ├── apiserver-kubelet-client.crt
                │   │           ├── apiserver-kubelet-client.key
                │   │           ├── apiserver.crt
                │   │           ├── apiserver.key
                │   │           ├── controller-manager.crt
                │   │           ├── controller-manager.key
                │   │           ├── etcd
                │   │           │   ├── etcd-healthcheck-client.crt
                │   │           │   ├── etcd-healthcheck-client.key
                │   │           │   ├── peer.crt
                │   │           │   ├── peer.key
                │   │           │   ├── server.crt
                │   │           │   └── server.key
                │   │           ├── front-proxy-client.crt
                │   │           ├── front-proxy-client.key
                │   │           ├── kube-proxy.crt
                │   │           ├── kube-proxy.key
                │   │           ├── kubelet.crt
                │   │           ├── kubelet.key
                │   │           ├── scheduler.crt
                │   │           └── scheduler.key
                │   └── var
                │       └── lib
                │           └── kubelet
                │               └── pki
                │                   ├── kubelet.crt
                │                   └── kubelet.key
                ├── worker001.local.kubernetes.example.com
                │   ├── etc
                │   │   └── kubernetes
                │   │       └── pki
                │   │           ├── front-proxy-client.crt
                │   │           ├── front-proxy-client.key
                │   │           ├── kube-proxy.crt
                │   │           ├── kube-proxy.key
                │   │           ├── kubelet.crt
                │   │           └── kubelet.key
                │   └── var
                │       └── lib
                │           └── kubelet
                │               └── pki
                │                   ├── kubelet.crt
                │                   └── kubelet.key
                ├── worker002.local.kubernetes.example.com
                │   ├── etc
                │   │   └── kubernetes
                │   │       └── pki
                │   │           ├── front-proxy-client.crt
                │   │           ├── front-proxy-client.key
                │   │           ├── kube-proxy.crt
                │   │           ├── kube-proxy.key
                │   │           ├── kubelet.crt
                │   │           └── kubelet.key
                │   └── var
                │       └── lib
                │           └── kubelet
                │               └── pki
                │                   ├── kubelet.crt
                │                   └── kubelet.key
                └── worker003.local.kubernetes.example.com
                    ├── etc
                    │   └── kubernetes
                    │       └── pki
                    │           ├── front-proxy-client.crt
                    │           ├── front-proxy-client.key
                    │           ├── kube-proxy.crt
                    │           ├── kube-proxy.key
                    │           ├── kubelet.crt
                    │           └── kubelet.key
                    └── var
                        └── lib
                            └── kubelet
                                └── pki
                                    ├── kubelet.crt
                                    └── kubelet.key

52 directories, 85 files
```


## test