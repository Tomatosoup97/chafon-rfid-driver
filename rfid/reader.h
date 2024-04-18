/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/cdev.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/module.h>

#define LOG_ENABLED 1

// TODO: Expose all of them to the userspace via generic IOCTL_RUN_COMMAND
enum cmd_type {
	// Action commands
	CMD_TAG_INVENTORY = 0x01,
	CMD_READ_DATA = 0x02,
	CMD_WRITE_DATA = 0x03,
	CMD_WRITE_EPC = 0x04,
	CMD_KILL_TAG = 0x05,
	CMD_SET_PROTECTION = 0x06,
	CMD_ERASE_BLOCK = 0x07,
	CMD_READ_PROTECTION_EPC = 0x08,
	CMD_READ_PROTECTION_NO_EPC = 0x09,
	CMD_UNLOCK_READ_PROTECTION = 0x0a,
	CMD_READ_PROTECTION_STATUS_CHECK = 0x0b,
	CMD_EAS_CONFIGURATION = 0x0c,
	CMD_EAS_ALERT_DETECTION = 0x0d,
	CMD_SINGLE_TAG_INVENTORY = 0x0f,
	CMD_WRITE_BLOCKS = 0x10,
	CMD_GET_MONZA_4QT_WORKING_PARAMETERS = 0x11,
	CMD_SET_MONZA_4QT_WORKING_PARAMETERS = 0x12,
	CMD_READ_EXTENDED_DATA = 0x15,
	CMD_WRITE_EXTENDED_DATA = 0x16,
	CMD_TAG_INVENTORY_WITH_MEMORY_BUFFER = 0x18,
	CMD_MIX_INVENTORY = 0x19,
	CMD_INVENTORY_EPC = 0x1a,
	CMD_QT_INVENTORY = 0x1b,

	// Config commands
	CF_GET_READER_INFO = 0x21,
	CF_SET_WORKING_FREQUENCY = 0x22,
	CF_SET_READER_ADDRESS = 0x24,
	CF_SET_READER_INVENTORY_TIME = 0x25,
	CF_SET_SERIAL_BAUD_RATE = 0x28,
	CF_SET_RF_POWER = 0x2f,
	CF_SET_WORK_MODE_288M = 0x76,
	CF_SET_WORK_MODE_18 = 0x35,
	CF_SET_BUZZER_ENABLED = 0x40,
	CF_SET_ACCOUSTO_OPTIC_TIMES = 0x33
};

// Constants
#define CMD_RESPONSE_BUFFER_SIZE 256
#define CRC_POLYNOMIAL 0x8408
#define INITIAL_CRC 0xFFFF

// Constraints
#define MAX_POWER 30
#define MAX_SCAN_TIME 0xFF
#define MIN_SCAN_TIME 0x03
#define EPC_MAX_LEN 256

struct reader_command {
	u8 addr;
	enum cmd_type cmd;
	u8 size;
	u8 *data;
};

struct reader_response {
	u8 size;
	u8 reader_addr;
	u8 resp_cmd;
	u8 status;
	u8 *data;
};

struct inventory_tag {
	u8 rssi;
	u8 epc_len;
	u8 epc[EPC_MAX_LEN];
};

struct inventory_data {
	u8 antenna;
	u8 num_tags;
	struct inventory_tag **tags;
};

struct rfid_reader {
	struct miscdevice misc;
	struct fd dev_fd;
	struct device *dev;
};

#if LOG_ENABLED
	#define LOG_ENTRY_LINE(dev) \
		dev_info(dev, "[%s:%d] %s: ", __FILE__, __LINE__, __func__)
#else
	#define LOG_ENTRY_LINE(...) do { } while (0)
#endif

#if LOG_ENABLED
	#define LOG_NO_NEWLINE(dev, ...) \
		do { \
			typeof(dev) _dev = dev; \
			LOG_ENTRY_LINE(_dev); \
			dev_info(_dev, __VA_ARGS__); \
		} while (0)
#else
	#define LOG_NO_NEWLINE(...) do { } while (0)
#endif

#if LOG_ENABLED
	#define LOG(dev, ...) \
		do { \
			typeof(dev) _dev = dev; \
			LOG_NO_NEWLINE(_dev, __VA_ARGS__); \
			dev_info(_dev,  "\n"); \
		} while (0)
#else
	#define LOG(...) do { } while (0)
#endif

#if LOG_ENABLED
	#define SECTION_LOG(dev, ...) \
		do { \
			typeof(dev) _dev = dev; \
			LOG_ENTRY_LINE(_dev); \
			dev_info(_dev, "-----"); \
			dev_info(_dev, __VA_ARGS__); \
			dev_info(_dev, "-----"); \
			dev_info(_dev, "\n"); \
		} while (0)
#else
	#define SECTION_LOG(...) do { } while (0)
#endif

#if LOG_ENABLED
	#define QUIET_LOG(dev, ...) dev_info(dev, __VA_ARGS__)
#else
	#define QUIET_LOG(...) do { } while (0)
#endif

#define SHOW_BUFFER_CONTENTS(dev, buffer, size) \
	do { \
		typeof(dev) _dev = dev; \
		for (ssize_t i = 0; i < (size); i++) { \
			QUIET_LOG(_dev, "%02X ", (buffer)[i]); \
		} \
	} while (0)

#define SHOW_BUFFER(dev, action, buffer, size) \
	do { \
		typeof(size) _size = size; \
		typeof(dev) _dev = dev; \
		LOG_NO_NEWLINE(_dev, "%s %zd bytes: ", action, _size); \
		SHOW_BUFFER_CONTENTS(_dev, (buffer), _size); \
		QUIET_LOG(_dev, "\n"); \
	} while (0)

#define SHOW_READER_COMMAND(dev, reader_cmd) \
	do { \
		typeof(cmd) _cmd = reader_cmd; \
		typeof(dev) _dev = dev; \
		LOG(_dev, "<ReaderCommand: addr=0x%02X, cmd=0x%02X, size=0x%02X >", \
			(_cmd)->addr, (_cmd)->cmd, (_cmd)->size); \
		if ((_cmd)->size) { \
			SHOW_BUFFER(_dev, \
				    "Reader command data has", \
				    (_cmd)->data, \
				    (ssize_t)(_cmd)->size); \
		} \
	} while (0)

#define SHOW_READER_RESPONSE(dev, resp) \
	do { \
		typeof(cmd) _resp = resp; \
		typeof(dev) _dev = dev; \
		LOG(_dev, \
		    "<ReaderResponse: size=0x%02X, addr=0x%02X, resp_cmd=0x%02X, status=0x%02X >", \
		    (_resp)->size, (_resp)->reader_addr, (_resp)->resp_cmd, (_resp)->status); \
		if ((_resp)->size) { \
			SHOW_BUFFER(_dev, \
				    "Received response of", \
				    (_resp)->data, \
				    (ssize_t)(_resp)->size); \
		} \
	} while (0)

#define SHOW_INVENTORY_TAG(dev, tag) \
	do { \
		typeof(tag) _tag = tag; \
		typeof(dev) _dev = dev; \
		if (searched_epc_len > 0 && \
			(memcmp((_tag)->epc, searched_epc, searched_epc_len) == 0)) { \
			QUIET_LOG(_dev, "[*FOUND*]"); \
		} \
		QUIET_LOG(_dev, "<Tag: "); \
		QUIET_LOG(_dev, "rssi=%u, ", (_tag)->rssi); \
		QUIET_LOG(_dev, "epc_len=%u, ", (_tag)->epc_len); \
		QUIET_LOG(_dev, "epc="); \
		for (size_t i = 0; i < (_tag)->epc_len; ++i) { \
			QUIET_LOG(_dev, "%02X ", (_tag)->epc[i]); \
		} \
		QUIET_LOG(_dev, ">\n"); \
	} while (0)

#define SHOW_INVENTORY_DATA(dev, inv) \
	do { \
		typeof(inv) _inv = inv; \
		typeof(dev) _dev = dev; \
		QUIET_LOG(_dev, "<Inventory Data: "); \
		QUIET_LOG(_dev, "Antenna=%u, ", (_inv)->antenna); \
		QUIET_LOG(_dev, "#Tags=%u>\n", (_inv)->num_tags); \
		for (size_t i = 0; i < (_inv)->num_tags; ++i) { \
			QUIET_LOG(_dev, "[%zu] ", i + 1); \
			SHOW_INVENTORY_TAG(_dev, (_inv)->tags[i]); \
		} \
	} while (0)

#define CRC_MSB(crc) ((crc) >> 8)
#define CRC_LSB(crc) ((crc) & 0xFF)

int write_frame(struct rfid_reader *reader,
		struct file *serial_file,
		struct reader_command *cmd);

ssize_t read_frame(struct file *serial_file, uint8_t *buffer);

int run_command(struct rfid_reader *reader,
		struct file *serial_file,
		struct reader_command *cmd,
		struct reader_response *reader_resp);

int set_buzzer(struct rfid_reader *reader, struct file *serial_file, uint8_t value);

int set_power(struct rfid_reader *reader, struct file *serial_file, uint8_t value);

int set_scan_time(struct rfid_reader *reader, struct file *serial_file, uint8_t value);

int parse_inventory_data(struct rfid_reader *reader,
			 struct reader_response *resp,
			 struct inventory_data *inventory);

void free_inventory_data(struct inventory_data *inventory);

int read_tags(struct rfid_reader *reader, struct file *serial_file);
