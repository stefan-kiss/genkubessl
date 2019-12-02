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

# structure

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

### examples

```bash
./genkubessl kubecerts -basepath outputs/kubernetes.example.com/system \
    -apisans kapi.kubernetes.example.com/10.0.0.1 \
    -masters master001.local.kubernetes.example.com/10.10.1.70,master002.local.kubernetes.example.com/10.10.1.85 \
    -workers worker001.local.kubernetes.example.com/10.10.1.207,worker002.local.kubernetes.example.com/10.10.1.104,worker003.local.kubernetes.example.com/10.10.1.139 \
    -etcd master001.local.kubernetes.example.com/10.10.1.70,master002.local.kubernetes.example.com/10.10.1.85 \
    -users stefan.kiss/admin
```
