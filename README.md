# Kernel driver for Chafon RFID tags reader

Read RFID tags using the Chafon UHF-based readers via a kernel driver.

Was tested and confirmed to work on CF-RU5202 model. Other models while operate in a
may require adjustments in the code.

## User guide

1. Ensure that Chafon RFID reader is connected and exposed at `/dev/ttyUSB0`
1. Load the kernel driver module

    $ sudo insmod rfid_reader_m.ko

1. Invoke `SET_FILE` ioctl (see section below about IOCTL calls)
1. Adjust parameters if needed
1. Call `read` on the driver's file
1. The returned buffer shall be of type `inventory_data_t` (see [this file](./rfid/reader.h))

A working example on how to use and interact with the driver is presented in
[userspace_example](./userspace_example).

## Supported IOCTL calls to the driver:

For details about IOCTL themselves, please refer to the
[reference](https://man7.org/linux/man-pages/man2/ioctl.2.html)

- `SET_FILE (0x01)`: Sets file descriptor pointing to open serial file representing RFID
    reader to use by the driver. Obligatory command to run before attempting to read.

- `SET_SCAN_TIME (0x02)`: Set device's scan time. Integer value in range [3 - 255]

- `SET_POWER (0x03)`: Set device's power. Integer value in range [0 - 30]

- `SET_BUZZER (0x04)`: Enable or disable buzzer, sound effect during a scan. Pass 1 to
    enable and 0 to disable.
