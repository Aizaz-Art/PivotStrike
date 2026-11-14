module pivot-tool

go 1.24

require (
	github.com/google/uuid v1.6.0
	github.com/nicocha30/gvisor-ligolo v0.0.0-20230726075806-989fa2c0a413
	github.com/songgao/water v0.0.0-20200317203138-2b4b6d7c09d8
)

require (
	github.com/google/btree v1.1.2 // indirect
	github.com/hashicorp/yamux v0.1.2
	golang.org/x/sys v0.17.0 // indirect
	golang.org/x/time v0.5.0 // indirect
)

replace golang.org/x/time => github.com/golang/time v0.5.0

replace golang.org/x/sys => github.com/golang/sys v0.17.0

replace golang.org/x/mod => github.com/golang/mod v0.14.0
