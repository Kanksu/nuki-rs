# Command "nuki" to operate Nuki Smart Lock

## Pairing

```bash
nuki pair
```

For pairing, the center button on the smart lock
must be pressed at least for 5 seconds. The LED
will flash to indicate that the device is now pairable.
The command ```nuki``` will discover the pairable device
and try to pair it.

After successful pairing, the MAC address of the device
and the generated private key (shared key) will be stored
on local file system. Default file name: ".nuki-key".

## Get status

if the nuki smart lock has been paired sucessfully, the following command
will return the current state of the status.

```bash
nuki status
```

or use the following command to get a battery report:
```bash
nuki battery
```

## Lock/Unlock
to perform Lock or Unlock actions:
```bash
nuki lock
nuki unlock
nuki unlatch
```

## Help
to print command usage info:
```bash
nuki --help

Usage: nuki [OPTIONS] [COMMAND]

Commands:
  status   Query current status (Default command)
  lock     Perform unlock action
  unlock   Perfrom lock action
  unlatch  Perfom unlatch action
  battery  Query battery report
  pair     Pair a Nuki Smart Lock
  help     Print this message or the help of the given subcommand(s)

Options:
  -l, --log-level <LOG_LEVEL>  Log level (error, warn, info, debug, trace) [default: WARN]
  -k, --key-file <KEY_FILE>    Key file, Default ~/.nuki-key
  -h, --help                   Print help
  -V, --version                Print version

```