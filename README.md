# Holosocket
a simple websocket proxy

## Require
* python >= 3.5 (for `async` `await`)
* pycryptodomex (AES-GCM encrypt)
* PyYAML (parse yaml config file)
* uvloop (optional: better performance)
* aiodns
* cachetools (optional: cache DNS resolve result)

## Usage
```
usage: wslocal [-h] [-c CONFIG] [--debug]

holosocket local

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        config file
  --debug               debug mode
```

```
usage: wsserver [-h] [-c CONFIG] [-4] [--debug]

holosocket server

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        config file
  -4, --ipv4            ipv4 only
  --debug               debug mode
```

## Note
`config.yaml`

> ```
> server: 127.0.0.2
> # v6_server is optional, you can comment it to close this feature
> v6_server: ::1
> server_port: 1088
> # If you don't want to custom dns server, just comment the dns content
> dns:
>     - 8.8.8.8
>     - 2001:4860:4860::8888
> local: 127.0.0.2
> local_port: 1089
> password: test
```
