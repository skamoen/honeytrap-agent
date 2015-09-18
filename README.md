# Honeytrap Agent

Honeytrap Agent will listen on the configured ports and forward all traffic to Honeytrap. This allows to run Agent and Honeytrap on different locations, but keeping metadata as the address of the attacker. The Agent can be used as well to forward only certain traffic to Honeytrap, like forwarding only traffic from specific countries to Honeytrap.

## Compile

We're using gb as build tool.

```
go get github.com/constabulary/gb/...
gb build
```

## License
To be determined. All right reserved Remco Verhoef. 

