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
./kubesslcerts kubecerts \
-apisans kapi.example.org/10.0.0.1:127.0.0.1:1.1.1.1 \
-masters master01.example.org/10.1.0.1:10.1.0.2,master02.example.org/10.1.1.1:10.1.1.2 \
-workers worker01.example.org/10.1.0.1:10.1.0.2,worker02.example.org/10.1.1.1:10.1.1.2
```
