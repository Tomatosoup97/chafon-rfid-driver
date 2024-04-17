// SPDX-License-Identifier: GPL-2.0
/*
 * Driver for Chafon RFID tags reader
 * Copyright (c) 2024
 * Mateusz Urbańczyk <mateusz.urbanczyk97@gmail.com>
 */

#include <linux/fs.h>
#include <linux/file.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mod_devicetable.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/platform_device.h>

#include "reader.h"

#define READ_BUFFER_SIZE 512

enum ioctl_cmd {
	IOCTL_SET_FILE = _IO('d', 0x01),
	IOCTL_SET_SCAN_TIME = _IO('d', 0x02),
	IOCTL_SET_POWER = _IO('d', 0x03),
	IOCTL_SET_BUZZER = _IO('d', 0x04)
};

struct rfid_reader {
	struct miscdevice misc;
	struct fd dev_fd;
};

int set_driver_file(struct rfid_reader *priv, int fd)
{
	if (priv->dev_fd.file)
		fdput(priv->dev_fd);

	priv->dev_fd = fdget(fd);

	if (!priv->dev_fd.file)
		return -EBADF;

	return 0;
}

static long rfid_reader_ioctl(struct file *file,
			      unsigned int cmd,
			      unsigned long user_arg)
{
	int kernel_arg, ret;
	struct rfid_reader *priv;

	printk(KERN_NOTICE "[%s]: cmd=%u, arg=%lu\n", __func__, cmd, user_arg);

	priv = container_of(file->private_data, struct rfid_reader, misc);

	ret = copy_from_user(&kernel_arg, (int __user *)user_arg, sizeof(int));

	if (ret) {
		printk(KERN_NOTICE "[%s] ioctl failed copying from user: %d\n", __func__, ret);
		return -EFAULT;
	}

	switch (cmd) {
	case IOCTL_SET_FILE:
		ret = set_driver_file(priv, kernel_arg);
		if (ret != 0)
			return ret;
		break;
	case IOCTL_SET_SCAN_TIME:
		ret = set_scan_time(priv->dev_fd.file, (uint8_t)kernel_arg);
		if (ret != 0)
			return ret;
		break;
	case IOCTL_SET_POWER:
		ret = set_power(priv->dev_fd.file, (uint8_t)kernel_arg);
		if (ret != 0)
			return ret;
		break;
	case IOCTL_SET_BUZZER:
		ret = set_buzzer(priv->dev_fd.file, (uint8_t)kernel_arg);
		if (ret != 0)
			return ret;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static ssize_t rfid_reader_read(struct file *file,
				char __user *user_buff,
				size_t size,
				loff_t *offset)
{
	struct rfid_reader *priv;
	ssize_t num_bytes_read;
	char kernel_buffer[READ_BUFFER_SIZE];
	int code = translate_antenna_num(8);

	printk(KERN_NOTICE "[%s]: %d\n", __func__, code);

	priv = container_of(file->private_data, struct rfid_reader, misc);

	if (!priv->dev_fd.file)
		return -ENODEV;

	if (size > READ_BUFFER_SIZE) {
		printk(KERN_NOTICE "[%s]: reading too much: %d\n", __func__, size);
		return -ENOMEM;
	}

	read_tags(priv->dev_fd.file);

	num_bytes_read = 0;

	if (num_bytes_read < 0)
		return num_bytes_read;

	printk(KERN_NOTICE "[%s]: buffer:\n%s\n", __func__, kernel_buffer);

	if (copy_to_user(user_buff, kernel_buffer, num_bytes_read))
		return -EFAULT;

	return num_bytes_read;
}

static int rfid_reader_release(struct inode *inode, struct file *file)
{
	struct rfid_reader *priv;

	priv = container_of(file->private_data, struct rfid_reader, misc);

	if (priv->dev_fd.file)
		fdput(priv->dev_fd);

	file->private_data = NULL;
	return 0;
}

static int rfid_reader_open(struct inode *inode, struct file *file)
{
	// noop
	return 0;
}

const struct file_operations rfid_reader_fops = {
	.owner = THIS_MODULE,
	.read = rfid_reader_read,
	.open = rfid_reader_open,
	.release = rfid_reader_release,
	.unlocked_ioctl = rfid_reader_ioctl,
};

static int rfid_reader_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct rfid_reader *priv;
	int ret;

	priv = devm_kzalloc(dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	priv->misc.parent = dev;
	priv->misc.name = "rfid-reader";
	priv->misc.minor = MISC_DYNAMIC_MINOR;
	priv->misc.fops = &rfid_reader_fops;

	ret = misc_register(&priv->misc);
	if (ret) {
		dev_err(dev, "Unable to register misc device\n");
		return ret;
	}

	dev_set_drvdata(dev, priv);

	return 0;
}

static int rfid_reader_remove(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct rfid_reader *priv = dev_get_drvdata(dev);

	misc_deregister(&priv->misc);
	return 0;
}

static const struct of_device_id rfid_reader_of_match[] = {
	{ .compatible = "rfid-reader" },
	{},
};
MODULE_DEVICE_TABLE(of, rfid_reader_of_match);

static struct platform_driver rfid_reader_driver = {
	.driver = {
		.name = "rfid-reader",
		.of_match_table = rfid_reader_of_match,
	},
	.probe = rfid_reader_probe,
	.remove = rfid_reader_remove,
};

module_platform_driver(rfid_reader_driver);

MODULE_DESCRIPTION("Proxy char driver");
MODULE_AUTHOR("Mateusz Urbańczyk <mateusz.urbanczyk97@gmail.com>");
MODULE_LICENSE("GPL");
