// SPDX-License-Identifier: GPL-2.0
/*
 * Driver for Raspberry Pi RP1 GPIO unit (pinctrl + GPIO)
 *
 * Copyright (C) 2023 Raspberry Pi Ltd.
 *
 * This driver is inspired by:
 * pinctrl-bcm2835.c, please see original file for copyright information
 */

#include <linux/bitmap.h>
#include <linux/bitops.h>
#include <linux/bug.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/gpio/driver.h>
#include <linux/io.h>
#include <linux/irq.h>
#include <linux/irqdesc.h>
#include <linux/init.h>
#include <linux/of_address.h>
#include <linux/of.h>
#include <linux/of_irq.h>
#include <linux/pinctrl/consumer.h>
#include <linux/pinctrl/machine.h>
#include <linux/pinctrl/pinconf.h>
#include <linux/pinctrl/pinctrl.h>
#include <linux/pinctrl/pinmux.h>
#include <linux/pinctrl/pinconf-generic.h>
#include <linux/platform_device.h>
#include <linux/seq_file.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include "core.h"
#include "pinconf.h"
#include "pinctrl-utils.h"

#define MODULE_NAME "pinctrl-rp1"
#define RP1_NUM_GPIOS	54
#define RP1_NUM_BANKS	3

#define RP1_RW_OFFSET			0x0000
#define RP1_XOR_OFFSET			0x1000
#define RP1_SET_OFFSET			0x2000
#define RP1_CLR_OFFSET			0x3000

#define RP1_GPIO_STATUS			0x0000
#define RP1_GPIO_CTRL			0x0004

#define RP1_GPIO_PCIE_INTE		0x011c
#define RP1_GPIO_PCIE_INTS		0x0124

#define RP1_GPIO_EVENTS_SHIFT_RAW	20
#define RP1_GPIO_STATUS_FALLING		BIT(20)
#define RP1_GPIO_STATUS_RISING		BIT(21)
#define RP1_GPIO_STATUS_LOW		BIT(22)
#define RP1_GPIO_STATUS_HIGH		BIT(23)

#define RP1_GPIO_EVENTS_SHIFT_FILTERED	24
#define RP1_GPIO_STATUS_F_FALLING	BIT(24)
#define RP1_GPIO_STATUS_F_RISING	BIT(25)
#define RP1_GPIO_STATUS_F_LOW		BIT(26)
#define RP1_GPIO_STATUS_F_HIGH		BIT(27)

#define RP1_GPIO_CTRL_FUNCSEL_LSB	0
#define RP1_GPIO_CTRL_FUNCSEL_MASK	0x0000001f
#define RP1_GPIO_CTRL_OUTOVER_LSB	12
#define RP1_GPIO_CTRL_OUTOVER_MASK	0x00003000
#define RP1_GPIO_CTRL_OEOVER_LSB	14
#define RP1_GPIO_CTRL_OEOVER_MASK	0x0000c000
#define RP1_GPIO_CTRL_INOVER_LSB	16
#define RP1_GPIO_CTRL_INOVER_MASK	0x00030000
#define RP1_GPIO_CTRL_IRQEN_FALLING	BIT(20)
#define RP1_GPIO_CTRL_IRQEN_RISING	BIT(21)
#define RP1_GPIO_CTRL_IRQEN_LOW		BIT(22)
#define RP1_GPIO_CTRL_IRQEN_HIGH	BIT(23)
#define RP1_GPIO_CTRL_IRQEN_F_FALLING	BIT(24)
#define RP1_GPIO_CTRL_IRQEN_F_RISING	BIT(25)
#define RP1_GPIO_CTRL_IRQEN_F_LOW	BIT(26)
#define RP1_GPIO_CTRL_IRQEN_F_HIGH	BIT(27)
#define RP1_GPIO_CTRL_IRQRESET		BIT(28)
#define RP1_GPIO_CTRL_IRQOVER_LSB	30
#define RP1_GPIO_CTRL_IRQOVER_MASK	0xc0000000

#define RP1_INT_EDGE_FALLING		BIT(0)
#define RP1_INT_EDGE_RISING		BIT(1)
#define RP1_INT_LEVEL_LOW		BIT(2)
#define RP1_INT_LEVEL_HIGH		BIT(3)
#define RP1_INT_MASK			0xf

#define RP1_INT_EDGE_BOTH		(RP1_INT_EDGE_FALLING |	\
					 RP1_INT_EDGE_RISING)
#define RP1_PUD_OFF			0
#define RP1_PUD_DOWN			1
#define RP1_PUD_UP			2

#define RP1_FSEL_COUNT			9

#define RP1_FSEL_ALT0			0x00
#define RP1_FSEL_GPIO			0x05
#define RP1_FSEL_NONE			0x09
#define RP1_FSEL_NONE_HW		0x1f

#define RP1_DIR_OUTPUT			0
#define RP1_DIR_INPUT			1

#define RP1_OUTOVER_PERI		0
#define RP1_OUTOVER_INVPERI		1
#define RP1_OUTOVER_LOW			2
#define RP1_OUTOVER_HIGH		3

#define RP1_OEOVER_PERI			0
#define RP1_OEOVER_INVPERI		1
#define RP1_OEOVER_DISABLE		2
#define RP1_OEOVER_ENABLE		3

#define RP1_INOVER_PERI			0
#define RP1_INOVER_INVPERI		1
#define RP1_INOVER_LOW			2
#define RP1_INOVER_HIGH			3

#define RP1_RIO_OUT			0x00
#define RP1_RIO_OE			0x04
#define RP1_RIO_IN			0x08

#define RP1_PAD_SLEWFAST_MASK		0x00000001
#define RP1_PAD_SLEWFAST_LSB		0
#define RP1_PAD_SCHMITT_MASK		0x00000002
#define RP1_PAD_SCHMITT_LSB		1
#define RP1_PAD_PULL_MASK		0x0000000c
#define RP1_PAD_PULL_LSB		2
#define RP1_PAD_DRIVE_MASK		0x00000030
#define RP1_PAD_DRIVE_LSB		4
#define RP1_PAD_IN_ENABLE_MASK		0x00000040
#define RP1_PAD_IN_ENABLE_LSB		6
#define RP1_PAD_OUT_DISABLE_MASK	0x00000080
#define RP1_PAD_OUT_DISABLE_LSB		7

#define RP1_PAD_DRIVE_2MA		0x00000000
#define RP1_PAD_DRIVE_4MA		0x00000010
#define RP1_PAD_DRIVE_8MA		0x00000020
#define RP1_PAD_DRIVE_12MA		0x00000030

#define FLD_GET(r, f) (((r) & (f ## _MASK)) >> (f ## _LSB))
#define FLD_SET(r, f, v) r = (((r) & ~(f ## _MASK)) | ((v) << (f ## _LSB)))

#define FUNC(f) \
	[func_##f] = #f
#define RP1_MAX_FSEL 8
#define PIN(i, f0, f1, f2, f3, f4, f5, f6, f7, f8) \
	[i] = { \
		.funcs = { \
			func_##f0, \
			func_##f1, \
			func_##f2, \
			func_##f3, \
			func_##f4, \
			func_##f5, \
			func_##f6, \
			func_##f7, \
			func_##f8, \
		}, \
	}

#define LEGACY_MAP(n, f0, f1, f2, f3, f4, f5) \
	[n] = { \
		func_gpio, \
		func_gpio, \
		func_##f5, \
		func_##f4, \
		func_##f0, \
		func_##f1, \
		func_##f2, \
		func_##f3, \
	}

struct rp1_iobank_desc {
	int min_gpio;
	int num_gpios;
	int gpio_offset;
	int inte_offset;
	int ints_offset;
	int rio_offset;
	int pads_offset;
};

struct rp1_pin_info {
	u8 num;
	u8 bank;
	u8 offset;
	u8 fsel;
	u8 irq_type;

	void __iomem *gpio;
	void __iomem *rio;
	void __iomem *inte;
	void __iomem *ints;
	void __iomem *pad;
};

enum funcs {
	func_alt0,
	func_alt1,
	func_alt2,
	func_alt3,
	func_alt4,
	func_gpio,
	func_alt6,
	func_alt7,
	func_alt8,
	func_none,
	func_aaud,
	func_dcd0,
	func_dpi,
	func_dsi0_te_ext,
	func_dsi1_te_ext,
	func_dsr0,
	func_dtr0,
	func_gpclk0,
	func_gpclk1,
	func_gpclk2,
	func_gpclk3,
	func_gpclk4,
	func_gpclk5,
	func_i2c0,
	func_i2c1,
	func_i2c2,
	func_i2c3,
	func_i2c4,
	func_i2c5,
	func_i2c6,
	func_i2s0,
	func_i2s1,
	func_i2s2,
	func_ir,
	func_mic,
	func_pcie_clkreq_n,
	func_pio,
	func_proc_rio,
	func_pwm0,
	func_pwm1,
	func_ri0,
	func_sd0,
	func_sd1,
	func_spi0,
	func_spi1,
	func_spi2,
	func_spi3,
	func_spi4,
	func_spi5,
	func_spi6,
	func_spi7,
	func_spi8,
	func_uart0,
	func_uart1,
	func_uart2,
	func_uart3,
	func_uart4,
	func_uart5,
	func_vbus0,
	func_vbus1,
	func_vbus2,
	func_vbus3,
	func__,
	func_count = func__,
	func_invalid = func__,
};

struct rp1_pin_funcs {
	u8 funcs[RP1_FSEL_COUNT];
};

struct rp1_pinctrl {
	struct device *dev;
	void __iomem *gpio_base;
	void __iomem *rio_base;
	void __iomem *pads_base;
	int irq[RP1_NUM_BANKS];
	struct rp1_pin_info pins[RP1_NUM_GPIOS];

	struct pinctrl_dev *pctl_dev;
	struct gpio_chip gpio_chip;
	struct pinctrl_gpio_range gpio_range;

	raw_spinlock_t irq_lock[RP1_NUM_BANKS];
};

const struct rp1_iobank_desc rp1_iobanks[RP1_NUM_BANKS] = {
	/*         gpio   inte    ints     rio    pads */
	{  0, 28, 0x0000, 0x011c, 0x0124, 0x0000, 0x0004 },
	{ 28,  6, 0x4000, 0x411c, 0x4124, 0x4000, 0x4004 },
	{ 34, 20, 0x8000, 0x811c, 0x8124, 0x8000, 0x8004 },
};

/* pins are just named GPIO0..GPIO53 */
#define RP1_GPIO_PIN(a) PINCTRL_PIN(a, "gpio" #a)
static struct pinctrl_pin_desc rp1_gpio_pins[] = {
	RP1_GPIO_PIN(0),
	RP1_GPIO_PIN(1),
	RP1_GPIO_PIN(2),
	RP1_GPIO_PIN(3),
	RP1_GPIO_PIN(4),
	RP1_GPIO_PIN(5),
	RP1_GPIO_PIN(6),
	RP1_GPIO_PIN(7),
	RP1_GPIO_PIN(8),
	RP1_GPIO_PIN(9),
	RP1_GPIO_PIN(10),
	RP1_GPIO_PIN(11),
	RP1_GPIO_PIN(12),
	RP1_GPIO_PIN(13),
	RP1_GPIO_PIN(14),
	RP1_GPIO_PIN(15),
	RP1_GPIO_PIN(16),
	RP1_GPIO_PIN(17),
	RP1_GPIO_PIN(18),
	RP1_GPIO_PIN(19),
	RP1_GPIO_PIN(20),
	RP1_GPIO_PIN(21),
	RP1_GPIO_PIN(22),
	RP1_GPIO_PIN(23),
	RP1_GPIO_PIN(24),
	RP1_GPIO_PIN(25),
	RP1_GPIO_PIN(26),
	RP1_GPIO_PIN(27),
	RP1_GPIO_PIN(28),
	RP1_GPIO_PIN(29),
	RP1_GPIO_PIN(30),
	RP1_GPIO_PIN(31),
	RP1_GPIO_PIN(32),
	RP1_GPIO_PIN(33),
	RP1_GPIO_PIN(34),
	RP1_GPIO_PIN(35),
	RP1_GPIO_PIN(36),
	RP1_GPIO_PIN(37),
	RP1_GPIO_PIN(38),
	RP1_GPIO_PIN(39),
	RP1_GPIO_PIN(40),
	RP1_GPIO_PIN(41),
	RP1_GPIO_PIN(42),
	RP1_GPIO_PIN(43),
	RP1_GPIO_PIN(44),
	RP1_GPIO_PIN(45),
	RP1_GPIO_PIN(46),
	RP1_GPIO_PIN(47),
	RP1_GPIO_PIN(48),
	RP1_GPIO_PIN(49),
	RP1_GPIO_PIN(50),
	RP1_GPIO_PIN(51),
	RP1_GPIO_PIN(52),
	RP1_GPIO_PIN(53),
};

/* one pin per group */
static const char * const rp1_gpio_groups[] = {
	"gpio0",
	"gpio1",
	"gpio2",
	"gpio3",
	"gpio4",
	"gpio5",
	"gpio6",
	"gpio7",
	"gpio8",
	"gpio9",
	"gpio10",
	"gpio11",
	"gpio12",
	"gpio13",
	"gpio14",
	"gpio15",
	"gpio16",
	"gpio17",
	"gpio18",
	"gpio19",
	"gpio20",
	"gpio21",
	"gpio22",
	"gpio23",
	"gpio24",
	"gpio25",
	"gpio26",
	"gpio27",
	"gpio28",
	"gpio29",
	"gpio30",
	"gpio31",
	"gpio32",
	"gpio33",
	"gpio34",
	"gpio35",
	"gpio36",
	"gpio37",
	"gpio38",
	"gpio39",
	"gpio40",
	"gpio41",
	"gpio42",
	"gpio43",
	"gpio44",
	"gpio45",
	"gpio46",
	"gpio47",
	"gpio48",
	"gpio49",
	"gpio50",
	"gpio51",
	"gpio52",
	"gpio53",
};

static const char * const rp1_func_names[] = {
	FUNC(alt0),
	FUNC(alt1),
	FUNC(alt2),
	FUNC(alt3),
	FUNC(alt4),
	FUNC(gpio),
	FUNC(alt6),
	FUNC(alt7),
	FUNC(alt8),
	FUNC(none),
	FUNC(aaud),
	FUNC(dcd0),
	FUNC(dpi),
	FUNC(dsi0_te_ext),
	FUNC(dsi1_te_ext),
	FUNC(dsr0),
	FUNC(dtr0),
	FUNC(gpclk0),
	FUNC(gpclk1),
	FUNC(gpclk2),
	FUNC(gpclk3),
	FUNC(gpclk4),
	FUNC(gpclk5),
	FUNC(i2c0),
	FUNC(i2c1),
	FUNC(i2c2),
	FUNC(i2c3),
	FUNC(i2c4),
	FUNC(i2c5),
	FUNC(i2c6),
	FUNC(i2s0),
	FUNC(i2s1),
	FUNC(i2s2),
	FUNC(ir),
	FUNC(mic),
	FUNC(pcie_clkreq_n),
	FUNC(pio),
	FUNC(proc_rio),
	FUNC(pwm0),
	FUNC(pwm1),
	FUNC(ri0),
	FUNC(sd0),
	FUNC(sd1),
	FUNC(spi0),
	FUNC(spi1),
	FUNC(spi2),
	FUNC(spi3),
	FUNC(spi4),
	FUNC(spi5),
	FUNC(spi6),
	FUNC(spi7),
	FUNC(spi8),
	FUNC(uart0),
	FUNC(uart1),
	FUNC(uart2),
	FUNC(uart3),
	FUNC(uart4),
	FUNC(uart5),
	FUNC(vbus0),
	FUNC(vbus1),
	FUNC(vbus2),
	FUNC(vbus3),
	[func_invalid] = "?"
};

static const struct rp1_pin_funcs rp1_gpio_pin_funcs[] = {
	PIN(0, spi0, dpi, uart1, i2c0, _, gpio, proc_rio, pio, spi2),
	PIN(1, spi0, dpi, uart1, i2c0, _, gpio, proc_rio, pio, spi2),
	PIN(2, spi0, dpi, uart1, i2c1, ir, gpio, proc_rio, pio, spi2),
	PIN(3, spi0, dpi, uart1, i2c1, ir, gpio, proc_rio, pio, spi2),
	PIN(4, gpclk0, dpi, uart2, i2c2, ri0, gpio, proc_rio, pio, spi3),
	PIN(5, gpclk1, dpi, uart2, i2c2, dtr0, gpio, proc_rio, pio, spi3),
	PIN(6, gpclk2, dpi, uart2, i2c3, dcd0, gpio, proc_rio, pio, spi3),
	PIN(7, spi0, dpi, uart2, i2c3, dsr0, gpio, proc_rio, pio, spi3),
	PIN(8, spi0, dpi, uart3, i2c0, _, gpio, proc_rio, pio, spi4),
	PIN(9, spi0, dpi, uart3, i2c0, _, gpio, proc_rio, pio, spi4),
	PIN(10, spi0, dpi, uart3, i2c1, _, gpio, proc_rio, pio, spi4),
	PIN(11, spi0, dpi, uart3, i2c1, _, gpio, proc_rio, pio, spi4),
	PIN(12, pwm0, dpi, uart4, i2c2, aaud, gpio, proc_rio, pio, spi5),
	PIN(13, pwm0, dpi, uart4, i2c2, aaud, gpio, proc_rio, pio, spi5),
	PIN(14, pwm0, dpi, uart4, i2c3, uart0, gpio, proc_rio, pio, spi5),
	PIN(15, pwm0, dpi, uart4, i2c3, uart0, gpio, proc_rio, pio, spi5),
	PIN(16, spi1, dpi, dsi0_te_ext, _, uart0, gpio, proc_rio, pio, _),
	PIN(17, spi1, dpi, dsi1_te_ext, _, uart0, gpio, proc_rio, pio, _),
	PIN(18, spi1, dpi, i2s0, pwm0, i2s1, gpio, proc_rio, pio, gpclk1),
	PIN(19, spi1, dpi, i2s0, pwm0, i2s1, gpio, proc_rio, pio, _),
	PIN(20, spi1, dpi, i2s0, gpclk0, i2s1, gpio, proc_rio, pio, _),
	PIN(21, spi1, dpi, i2s0, gpclk1, i2s1, gpio, proc_rio, pio, _),
	PIN(22, sd0, dpi, i2s0, i2c3, i2s1, gpio, proc_rio, pio, _),
	PIN(23, sd0, dpi, i2s0, i2c3, i2s1, gpio, proc_rio, pio, _),
	PIN(24, sd0, dpi, i2s0, _, i2s1, gpio, proc_rio, pio, spi2),
	PIN(25, sd0, dpi, i2s0, mic, i2s1, gpio, proc_rio, pio, spi3),
	PIN(26, sd0, dpi, i2s0, mic, i2s1, gpio, proc_rio, pio, spi5),
	PIN(27, sd0, dpi, i2s0, mic, i2s1, gpio, proc_rio, pio, spi1),
	PIN(28, sd1, i2c4, i2s2, spi6, vbus0, gpio, proc_rio, _, _),
	PIN(29, sd1, i2c4, i2s2, spi6, vbus0, gpio, proc_rio, _, _),
	PIN(30, sd1, i2c5, i2s2, spi6, uart5, gpio, proc_rio, _, _),
	PIN(31, sd1, i2c5, i2s2, spi6, uart5, gpio, proc_rio, _, _),
	PIN(32, sd1, gpclk3, i2s2, spi6, uart5, gpio, proc_rio, _, _),
	PIN(33, sd1, gpclk4, i2s2, spi6, uart5, gpio, proc_rio, _, _),
	PIN(34, pwm1, gpclk3, vbus0, i2c4, mic, gpio, proc_rio, _, _),
	PIN(35, spi8, pwm1, vbus0, i2c4, mic, gpio, proc_rio, _, _),
	PIN(36, spi8, uart5, pcie_clkreq_n, i2c5, mic, gpio, proc_rio, _, _),
	PIN(37, spi8, uart5, mic, i2c5, pcie_clkreq_n, gpio, proc_rio, _, _),
	PIN(38, spi8, uart5, mic, i2c6, aaud, gpio, proc_rio, dsi0_te_ext, _),
	PIN(39, spi8, uart5, mic, i2c6, aaud, gpio, proc_rio, dsi1_te_ext, _),
	PIN(40, pwm1, uart5, i2c4, spi6, aaud, gpio, proc_rio, _, _),
	PIN(41, pwm1, uart5, i2c4, spi6, aaud, gpio, proc_rio, _, _),
	PIN(42, gpclk5, uart5, vbus1, spi6, i2s2, gpio, proc_rio, _, _),
	PIN(43, gpclk4, uart5, vbus1, spi6, i2s2, gpio, proc_rio, _, _),
	PIN(44, gpclk5, i2c5, pwm1, spi6, i2s2, gpio, proc_rio, _, _),
	PIN(45, pwm1, i2c5, spi7, spi6, i2s2, gpio, proc_rio, _, _),
	PIN(46, gpclk3, i2c4, spi7, mic, i2s2, gpio, proc_rio, dsi0_te_ext, _),
	PIN(47, gpclk5, i2c4, spi7, mic, i2s2, gpio, proc_rio, dsi1_te_ext, _),
	PIN(48, pwm1, pcie_clkreq_n, spi7, mic, uart5, gpio, proc_rio, _, _),
	PIN(49, spi8, spi7, i2c5, aaud, uart5, gpio, proc_rio, _, _),
	PIN(50, spi8, spi7, i2c5, aaud, vbus2, gpio, proc_rio, _, _),
	PIN(51, spi8, spi7, i2c6, aaud, vbus2, gpio, proc_rio, _, _),
	PIN(52, spi8, _, i2c6, aaud, vbus3, gpio, proc_rio, _, _),
	PIN(53, spi8, spi7, _, pcie_clkreq_n, vbus3, gpio, proc_rio, _, _),
};

static const u8 legacy_fsel_map[][8] = {
	LEGACY_MAP(0, i2c0, _, dpi, spi2, uart1, _),
	LEGACY_MAP(1, i2c0, _, dpi, spi2, uart1, _),
	LEGACY_MAP(2, i2c1, _, dpi, spi2, uart1, _),
	LEGACY_MAP(3, i2c1, _, dpi, spi2, uart1, _),
	LEGACY_MAP(4, gpclk0, _, dpi, spi3, uart2, i2c2),
	LEGACY_MAP(5, gpclk1, _, dpi, spi3, uart2, i2c2),
	LEGACY_MAP(6, gpclk2, _, dpi, spi3, uart2, i2c3),
	LEGACY_MAP(7, spi0, _, dpi, spi3, uart2, i2c3),
	LEGACY_MAP(8, spi0, _, dpi, _, uart3, i2c0),
	LEGACY_MAP(9, spi0, _, dpi, _, uart3, i2c0),
	LEGACY_MAP(10, spi0, _, dpi, _, uart3, i2c1),
	LEGACY_MAP(11, spi0, _, dpi, _, uart3, i2c1),
	LEGACY_MAP(12, pwm0, _, dpi, spi5, uart4, i2c2),
	LEGACY_MAP(13, pwm0, _, dpi, spi5, uart4, i2c2),
	LEGACY_MAP(14, uart0, _, dpi, spi5, uart4, _),
	LEGACY_MAP(15, uart0, _, dpi, spi5, uart4, _),
	LEGACY_MAP(16, _, _, dpi, uart0, spi1, _),
	LEGACY_MAP(17, _, _, dpi, uart0, spi1, _),
	LEGACY_MAP(18, i2s0, _, dpi, _, spi1, pwm0),
	LEGACY_MAP(19, i2s0, _, dpi, _, spi1, pwm0),
	LEGACY_MAP(20, i2s0, _, dpi, _, spi1, gpclk0),
	LEGACY_MAP(21, i2s0, _, dpi, _, spi1, gpclk1),
	LEGACY_MAP(22, sd0, _, dpi, _, _, i2c3),
	LEGACY_MAP(23, sd0, _, dpi, _, _, i2c3),
	LEGACY_MAP(24, sd0, _, dpi, _, _, spi2),
	LEGACY_MAP(25, sd0, _, dpi, _, _, spi3),
	LEGACY_MAP(26, sd0, _, dpi, _, _, spi5),
	LEGACY_MAP(27, sd0, _, dpi, _, _, _),
};

static const char * const irq_type_names[] = {
	[IRQ_TYPE_NONE] = "none",
	[IRQ_TYPE_EDGE_RISING] = "edge-rising",
	[IRQ_TYPE_EDGE_FALLING] = "edge-falling",
	[IRQ_TYPE_EDGE_BOTH] = "edge-both",
	[IRQ_TYPE_LEVEL_HIGH] = "level-high",
	[IRQ_TYPE_LEVEL_LOW] = "level-low",
};

static int rp1_pinconf_set(struct pinctrl_dev *pctldev,
			   unsigned int offset, unsigned long *configs,
			   unsigned int num_configs);

static struct rp1_pin_info *rp1_get_pin(struct gpio_chip *chip,
					unsigned int offset)
{
	struct rp1_pinctrl *pc = gpiochip_get_data(chip);

	if (pc && offset < RP1_NUM_GPIOS)
		return &pc->pins[offset];
	return NULL;
}

static struct rp1_pin_info *rp1_get_pin_pctl(struct pinctrl_dev *pctldev,
					     unsigned int offset)
{
	struct rp1_pinctrl *pc = pinctrl_dev_get_drvdata(pctldev);

	if (pc && offset < RP1_NUM_GPIOS)
		return &pc->pins[offset];
	return NULL;
}

static void rp1_pad_update(struct rp1_pin_info *pin, u32 clr, u32 set)
{
	u32 padctrl = readl(pin->pad);

	padctrl &= ~clr;
	padctrl |= set;

	writel(padctrl, pin->pad);
}

static void rp1_input_enable(struct rp1_pin_info *pin, int value)
{
	rp1_pad_update(pin, RP1_PAD_IN_ENABLE_MASK,
		       value ? RP1_PAD_IN_ENABLE_MASK : 0);
}

static void rp1_output_enable(struct rp1_pin_info *pin, int value)
{
	rp1_pad_update(pin, RP1_PAD_OUT_DISABLE_MASK,
		       value ? 0 : RP1_PAD_OUT_DISABLE_MASK);
}

static u32 rp1_get_fsel(struct rp1_pin_info *pin)
{
	u32 ctrl = readl(pin->gpio + RP1_GPIO_CTRL);
	u32 oeover = FLD_GET(ctrl, RP1_GPIO_CTRL_OEOVER);
	u32 fsel = FLD_GET(ctrl, RP1_GPIO_CTRL_FUNCSEL);

	if (oeover != RP1_OEOVER_PERI || fsel >= RP1_FSEL_COUNT)
		fsel = RP1_FSEL_NONE;

	return fsel;
}

static void rp1_set_fsel(struct rp1_pin_info *pin, u32 fsel)
{
	u32 ctrl = readl(pin->gpio + RP1_GPIO_CTRL);

	if (fsel >= RP1_FSEL_COUNT)
		fsel = RP1_FSEL_NONE_HW;

	rp1_input_enable(pin, 1);
	rp1_output_enable(pin, 1);

	if (fsel == RP1_FSEL_NONE) {
		FLD_SET(ctrl, RP1_GPIO_CTRL_OEOVER, RP1_OEOVER_DISABLE);
	} else {
		FLD_SET(ctrl, RP1_GPIO_CTRL_OUTOVER, RP1_OUTOVER_PERI);
		FLD_SET(ctrl, RP1_GPIO_CTRL_OEOVER, RP1_OEOVER_PERI);
	}
	FLD_SET(ctrl, RP1_GPIO_CTRL_FUNCSEL, fsel);
	writel(ctrl, pin->gpio + RP1_GPIO_CTRL);
}

static int rp1_get_dir(struct rp1_pin_info *pin)
{
	return !(readl(pin->rio + RP1_RIO_OE) & (1 << pin->offset)) ?
		RP1_DIR_INPUT : RP1_DIR_OUTPUT;
}

static void rp1_set_dir(struct rp1_pin_info *pin, bool is_input)
{
	int offset = is_input ? RP1_CLR_OFFSET : RP1_SET_OFFSET;

	writel(1 << pin->offset, pin->rio + RP1_RIO_OE + offset);
}

static int rp1_get_value(struct rp1_pin_info *pin)
{
	return !!(readl(pin->rio + RP1_RIO_IN) & (1 << pin->offset));
}

static void rp1_set_value(struct rp1_pin_info *pin, int value)
{
	/* Assume the pin is already an output */
	writel(1 << pin->offset,
	       pin->rio + RP1_RIO_OUT + (value ? RP1_SET_OFFSET : RP1_CLR_OFFSET));
}

static int rp1_gpio_get(struct gpio_chip *chip, unsigned offset)
{
	struct rp1_pin_info *pin = rp1_get_pin(chip, offset);
	int ret;

	if (!pin)
		return -EINVAL;
	ret = rp1_get_value(pin);
	return ret;
}

static void rp1_gpio_set(struct gpio_chip *chip, unsigned offset, int value)
{
	struct rp1_pin_info *pin = rp1_get_pin(chip, offset);

	if (pin)
		rp1_set_value(pin, value);
}

static int rp1_gpio_get_direction(struct gpio_chip *chip, unsigned int offset)
{
	struct rp1_pin_info *pin = rp1_get_pin(chip, offset);
	u32 fsel;

	if (!pin)
		return -EINVAL;
	fsel = rp1_get_fsel(pin);
	if (fsel != RP1_FSEL_GPIO)
		return -EINVAL;
	return (rp1_get_dir(pin) == RP1_DIR_OUTPUT) ?
		GPIO_LINE_DIRECTION_OUT :
		GPIO_LINE_DIRECTION_IN;
}

static int rp1_gpio_direction_input(struct gpio_chip *chip, unsigned offset)
{
	struct rp1_pin_info *pin = rp1_get_pin(chip, offset);

	if (!pin)
		return -EINVAL;
	rp1_set_dir(pin, RP1_DIR_INPUT);
	rp1_set_fsel(pin, RP1_FSEL_GPIO);
	return 0;
}

static int rp1_gpio_direction_output(struct gpio_chip *chip, unsigned offset,
				     int value)
{
	struct rp1_pin_info *pin = rp1_get_pin(chip, offset);

	if (!pin)
		return -EINVAL;
	rp1_set_value(pin, value);
	rp1_set_dir(pin, RP1_DIR_OUTPUT);
	rp1_set_fsel(pin, RP1_FSEL_GPIO);
	return 0;
}

static int rp1_gpio_set_config(struct gpio_chip *gc, unsigned offset,
			       unsigned long config)
{
	struct rp1_pinctrl *pc = gpiochip_get_data(gc);
	unsigned long configs[] = { config };

	return rp1_pinconf_set(pc->pctl_dev, offset, configs,
			      ARRAY_SIZE(configs));
}

static const struct gpio_chip rp1_gpio_chip = {
	.label = MODULE_NAME,
	.owner = THIS_MODULE,
	.request = gpiochip_generic_request,
	.free = gpiochip_generic_free,
	.direction_input = rp1_gpio_direction_input,
	.direction_output = rp1_gpio_direction_output,
	.get_direction = rp1_gpio_get_direction,
	.get = rp1_gpio_get,
	.set = rp1_gpio_set,
	.base = -1,
	.set_config = rp1_gpio_set_config,
	.ngpio = RP1_NUM_GPIOS,
	.can_sleep = false,
};

static void rp1_gpio_irq_handler(struct irq_desc *desc)
{
	struct gpio_chip *chip = irq_desc_get_handler_data(desc);
	struct rp1_pinctrl *pc = gpiochip_get_data(chip);
	struct irq_chip *host_chip = irq_desc_get_chip(desc);
	const struct rp1_iobank_desc *bank;
	int irq = irq_desc_get_irq(desc);
	unsigned long ints;
	int b;

	if (pc->irq[0] == irq)
		bank = &rp1_iobanks[0];
	else if (pc->irq[1] == irq)
		bank = &rp1_iobanks[1];
	else
		bank = &rp1_iobanks[2];

	chained_irq_enter(host_chip, desc);

	ints = readl(pc->gpio_base + bank->ints_offset);
	for_each_set_bit(b, &ints, 32) {
		struct rp1_pin_info *pin = rp1_get_pin(chip, b);

		writel(RP1_GPIO_CTRL_IRQRESET,
		       pin->gpio + RP1_SET_OFFSET + RP1_GPIO_CTRL);
		generic_handle_irq(irq_linear_revmap(pc->gpio_chip.irq.domain,
						     bank->gpio_offset + b));
	}

	chained_irq_exit(host_chip, desc);
}

static void rp1_gpio_irq_config(struct rp1_pin_info *pin, bool enable)
{
	writel(1 << pin->offset,
	       pin->inte + (enable ? RP1_SET_OFFSET : RP1_CLR_OFFSET));
	if (!enable)
		/* Clear any latched events */
		writel(RP1_GPIO_CTRL_IRQRESET,
		       pin->gpio + RP1_SET_OFFSET + RP1_GPIO_CTRL);
}

static void rp1_gpio_irq_enable(struct irq_data *data)
{
	struct gpio_chip *chip = irq_data_get_irq_chip_data(data);
	unsigned gpio = irqd_to_hwirq(data);
	struct rp1_pin_info *pin = rp1_get_pin(chip, gpio);

	rp1_gpio_irq_config(pin, true);
}

static void rp1_gpio_irq_disable(struct irq_data *data)
{
	struct gpio_chip *chip = irq_data_get_irq_chip_data(data);
	unsigned gpio = irqd_to_hwirq(data);
	struct rp1_pin_info *pin = rp1_get_pin(chip, gpio);

	rp1_gpio_irq_config(pin, false);
}

static int rp1_irq_set_type(struct rp1_pin_info *pin, unsigned int type)
{
	u32 irq_flags;

	switch (type) {
	case IRQ_TYPE_NONE:
		irq_flags = 0;
		break;
	case IRQ_TYPE_EDGE_RISING:
		irq_flags = RP1_INT_EDGE_RISING;
		break;
	case IRQ_TYPE_EDGE_FALLING:
		irq_flags = RP1_INT_EDGE_FALLING;
		break;
	case IRQ_TYPE_EDGE_BOTH:
		irq_flags = RP1_INT_EDGE_RISING | RP1_INT_EDGE_FALLING;
		break;
	case IRQ_TYPE_LEVEL_HIGH:
		irq_flags = RP1_INT_LEVEL_HIGH;
		break;
	case IRQ_TYPE_LEVEL_LOW:
		irq_flags = RP1_INT_LEVEL_LOW;
		break;

	default:
		return -EINVAL;
	}

	/* Clear them all */
	writel(RP1_INT_MASK << RP1_GPIO_EVENTS_SHIFT_RAW,
	       pin->gpio + RP1_CLR_OFFSET + RP1_GPIO_CTRL);
	/* Set those that are needed */
	writel(irq_flags << RP1_GPIO_EVENTS_SHIFT_RAW,
	       pin->gpio + RP1_SET_OFFSET + RP1_GPIO_CTRL);
	pin->irq_type = type;

	return 0;
}

static int rp1_gpio_irq_set_type(struct irq_data *data, unsigned int type)
{
	struct gpio_chip *chip = irq_data_get_irq_chip_data(data);
	struct rp1_pinctrl *pc = gpiochip_get_data(chip);
	unsigned gpio = irqd_to_hwirq(data);
	struct rp1_pin_info *pin = rp1_get_pin(chip, gpio);
	int bank = pin->bank;
	unsigned long flags;
	int ret;

	raw_spin_lock_irqsave(&pc->irq_lock[bank], flags);

	ret = rp1_irq_set_type(pin, type);
	if (!ret) {
		if (type & IRQ_TYPE_EDGE_BOTH)
			irq_set_handler_locked(data, handle_edge_irq);
		else
			irq_set_handler_locked(data, handle_level_irq);
	}

	raw_spin_unlock_irqrestore(&pc->irq_lock[bank], flags);

	return ret;
}

static void rp1_gpio_irq_ack(struct irq_data *data)
{
	struct gpio_chip *chip = irq_data_get_irq_chip_data(data);
	unsigned gpio = irqd_to_hwirq(data);
	struct rp1_pin_info *pin = rp1_get_pin(chip, gpio);

	/* Clear any latched events */
	writel(RP1_GPIO_CTRL_IRQRESET, pin->gpio + RP1_SET_OFFSET + RP1_GPIO_CTRL);
}

static struct irq_chip rp1_gpio_irq_chip = {
	.name = MODULE_NAME,
	.irq_enable = rp1_gpio_irq_enable,
	.irq_disable = rp1_gpio_irq_disable,
	.irq_set_type = rp1_gpio_irq_set_type,
	.irq_ack = rp1_gpio_irq_ack,
	.irq_mask = rp1_gpio_irq_disable,
	.irq_unmask = rp1_gpio_irq_enable,
	.flags = IRQCHIP_IMMUTABLE,
};

static int rp1_pctl_get_groups_count(struct pinctrl_dev *pctldev)
{
	return ARRAY_SIZE(rp1_gpio_groups);
}

static const char *rp1_pctl_get_group_name(struct pinctrl_dev *pctldev,
					   unsigned selector)
{
	return rp1_gpio_groups[selector];
}

static enum funcs rp1_get_fsel_func(unsigned pin, unsigned fsel)
{
	if (pin < RP1_NUM_GPIOS) {
		if (fsel < RP1_FSEL_COUNT)
			return rp1_gpio_pin_funcs[pin].funcs[fsel];
		else if (fsel == RP1_FSEL_NONE)
			return func_none;
	}
	return func_invalid;
}

static int rp1_pctl_get_group_pins(struct pinctrl_dev *pctldev,
				   unsigned selector,
				   const unsigned **pins,
				   unsigned *num_pins)
{
	*pins = &rp1_gpio_pins[selector].number;
	*num_pins = 1;

	return 0;
}

static void rp1_pctl_pin_dbg_show(struct pinctrl_dev *pctldev,
				  struct seq_file *s,
				  unsigned offset)
{
	struct rp1_pinctrl *pc = pinctrl_dev_get_drvdata(pctldev);
	struct gpio_chip *chip = &pc->gpio_chip;
	struct rp1_pin_info *pin = rp1_get_pin_pctl(pctldev, offset);
	u32 fsel = rp1_get_fsel(pin);
	enum funcs func = rp1_get_fsel_func(offset, fsel);
	int value = rp1_get_value(pin);
	int irq = irq_find_mapping(chip->irq.domain, offset);

	seq_printf(s, "function %s (%s) in %s; irq %d (%s)",
		   rp1_func_names[fsel], rp1_func_names[func],
		   value ? "hi" : "lo",
		   irq, irq_type_names[pin->irq_type]);
}

static void rp1_pctl_dt_free_map(struct pinctrl_dev *pctldev,
				 struct pinctrl_map *maps, unsigned num_maps)
{
	int i;

	for (i = 0; i < num_maps; i++)
		if (maps[i].type == PIN_MAP_TYPE_CONFIGS_PIN)
			kfree(maps[i].data.configs.configs);

	kfree(maps);
}

static int rp1_pctl_legacy_map_func(struct rp1_pinctrl *pc,
				    struct device_node *np, u32 pin, u32 fnum,
				    struct pinctrl_map *maps,
				    unsigned int *num_maps)
{
	struct pinctrl_map *map = &maps[*num_maps];
	enum funcs func;

	if (fnum >= ARRAY_SIZE(legacy_fsel_map[0])) {
		dev_err(pc->dev, "%pOF: invalid brcm,function %d\n", np, fnum);
		return -EINVAL;
	}

	func = legacy_fsel_map[pin][fnum];
	if (func == func_invalid) {
		dev_err(pc->dev, "%pOF: brcm,function %d not supported on pin %d\n",
			np, fnum, pin);
	}

	map->type = PIN_MAP_TYPE_MUX_GROUP;
	map->data.mux.group = rp1_gpio_groups[pin];
	map->data.mux.function = rp1_func_names[func];
	(*num_maps)++;

	return 0;
}

static int rp1_pctl_legacy_map_pull(struct rp1_pinctrl *pc,
				    struct device_node *np, u32 pin, u32 pull,
				    struct pinctrl_map *maps,
				    unsigned int *num_maps)
{
	struct pinctrl_map *map = &maps[*num_maps];
	enum pin_config_param param;
	unsigned long *configs;

	switch (pull) {
	case RP1_PUD_OFF:
		param = PIN_CONFIG_BIAS_DISABLE;
		break;
	case RP1_PUD_DOWN:
		param = PIN_CONFIG_BIAS_PULL_DOWN;
		break;
	case RP1_PUD_UP:
		param = PIN_CONFIG_BIAS_PULL_UP;
		break;
	default:
		dev_err(pc->dev, "%pOF: invalid brcm,pull %d\n", np, pull);
		return -EINVAL;
	}

	configs = kzalloc(sizeof(*configs), GFP_KERNEL);
	if (!configs)
		return -ENOMEM;

	configs[0] = pinconf_to_config_packed(param, 0);
	map->type = PIN_MAP_TYPE_CONFIGS_PIN;
	map->data.configs.group_or_pin = rp1_gpio_pins[pin].name;
	map->data.configs.configs = configs;
	map->data.configs.num_configs = 1;
	(*num_maps)++;

	return 0;
}

static int rp1_pctl_dt_node_to_map(struct pinctrl_dev *pctldev,
				   struct device_node *np,
				   struct pinctrl_map **map,
				   unsigned int *num_maps)
{
	struct rp1_pinctrl *pc = pinctrl_dev_get_drvdata(pctldev);
	struct property *pins, *funcs, *pulls;
	int num_pins, num_funcs, num_pulls, maps_per_pin;
	struct pinctrl_map *maps;
	unsigned long *configs = NULL;
	const char *function = NULL;
	unsigned int reserved_maps;
	int num_configs = 0;
	int i, err;
	u32 pin, func, pull;

	/* Check for legacy pin declaration */
	pins = of_find_property(np, "brcm,pins", NULL);

	if (!pins) /* Assume generic bindings in this node */
		return pinconf_generic_dt_node_to_map_all(pctldev, np, map, num_maps);

	funcs = of_find_property(np, "brcm,function", NULL);
	if (!funcs)
		of_property_read_string(np, "function", &function);

	pulls = of_find_property(np, "brcm,pull", NULL);
	if (!pulls)
		pinconf_generic_parse_dt_config(np, pctldev, &configs, &num_configs);

	if (!function && !funcs && !num_configs && !pulls) {
		dev_err(pc->dev,
			"%pOF: no function, brcm,function, brcm,pull, etc.\n",
			np);
		return -EINVAL;
	}

	num_pins = pins->length / 4;
	num_funcs = funcs ? (funcs->length / 4) : 0;
	num_pulls = pulls ? (pulls->length / 4) : 0;

	if (num_funcs > 1 && num_funcs != num_pins) {
		dev_err(pc->dev,
			"%pOF: brcm,function must have 1 or %d entries\n",
			np, num_pins);
		return -EINVAL;
	}

	if (num_pulls > 1 && num_pulls != num_pins) {
		dev_err(pc->dev,
			"%pOF: brcm,pull must have 1 or %d entries\n",
			np, num_pins);
		return -EINVAL;
	}

	maps_per_pin = 0;
	if (function || num_funcs)
		maps_per_pin++;
	if (num_configs || num_pulls)
		maps_per_pin++;
	reserved_maps = num_pins * maps_per_pin;
	maps = kcalloc(reserved_maps, sizeof(*maps), GFP_KERNEL);
	if (!maps)
		return -ENOMEM;

	*num_maps = 0;

	for (i = 0; i < num_pins; i++) {
		err = of_property_read_u32_index(np, "brcm,pins", i, &pin);
		if (err)
			goto out;
		if (pin >= ARRAY_SIZE(legacy_fsel_map)) {
			dev_err(pc->dev, "%pOF: invalid brcm,pins value %d\n",
				np, pin);
			err = -EINVAL;
			goto out;
		}

		if (num_funcs) {
			err = of_property_read_u32_index(np, "brcm,function",
							 (num_funcs > 1) ? i : 0,
							 &func);
			if (err)
				goto out;
			err = rp1_pctl_legacy_map_func(pc, np, pin, func,
						       maps, num_maps);
		} else if (function) {
			err = pinctrl_utils_add_map_mux(pctldev, &maps,
							&reserved_maps, num_maps,
							rp1_gpio_groups[pin],
							function);
		}

		if (err)
			goto out;

		if (num_pulls) {
			err = of_property_read_u32_index(np, "brcm,pull",
							 (num_pulls > 1) ? i : 0,
							 &pull);
			if (err)
				goto out;
			err = rp1_pctl_legacy_map_pull(pc, np, pin, pull,
						       maps, num_maps);
		} else if (num_configs) {
			err = pinctrl_utils_add_map_configs(pctldev, &maps,
							    &reserved_maps, num_maps,
							    rp1_gpio_groups[pin],
							    configs, num_configs,
							    PIN_MAP_TYPE_CONFIGS_PIN);
		}

		if (err)
			goto out;
	}

	*map = maps;

	return 0;

out:
	rp1_pctl_dt_free_map(pctldev, maps, reserved_maps);
	return err;
}

static const struct pinctrl_ops rp1_pctl_ops = {
	.get_groups_count = rp1_pctl_get_groups_count,
	.get_group_name = rp1_pctl_get_group_name,
	.get_group_pins = rp1_pctl_get_group_pins,
	.pin_dbg_show = rp1_pctl_pin_dbg_show,
	.dt_node_to_map = rp1_pctl_dt_node_to_map,
	.dt_free_map = rp1_pctl_dt_free_map,
};

static int rp1_pmx_free(struct pinctrl_dev *pctldev, unsigned offset)
{
	struct rp1_pin_info *pin = rp1_get_pin_pctl(pctldev, offset);
	u32 fsel = rp1_get_fsel(pin);

	/* Return non-GPIOs to GPIO_IN */
	if (fsel != RP1_FSEL_GPIO) {
		rp1_set_dir(pin, RP1_DIR_INPUT);
		rp1_set_fsel(pin, RP1_FSEL_GPIO);
	}

	return 0;
}

static int rp1_pmx_get_functions_count(struct pinctrl_dev *pctldev)
{
	return func_count;
}

static const char *rp1_pmx_get_function_name(struct pinctrl_dev *pctldev,
					     unsigned selector)
{
	return (selector < func_count) ? rp1_func_names[selector] : NULL;
}

static int rp1_pmx_get_function_groups(struct pinctrl_dev *pctldev,
				       unsigned selector,
				       const char * const **groups,
				       unsigned * const num_groups)
{
	/* every pin can do every function */
	*groups = rp1_gpio_groups;
	*num_groups = ARRAY_SIZE(rp1_gpio_groups);

	return 0;
}

static int rp1_pmx_set(struct pinctrl_dev *pctldev, unsigned func_selector,
		       unsigned group_selector)
{
	struct rp1_pin_info *pin = rp1_get_pin_pctl(pctldev, group_selector);
	const u8 *pin_funcs;
	int fsel;

	/* func_selector is an enum funcs, so needs translation */

	if (func_selector >= RP1_FSEL_COUNT) {
		/* Convert to an fsel number */
		pin_funcs = rp1_gpio_pin_funcs[pin->num].funcs;
		for (fsel = 0; fsel < RP1_FSEL_COUNT; fsel++) {
			if (pin_funcs[fsel] == func_selector)
				break;
		}
	} else {
		fsel = (int)func_selector;
	}

	if (fsel >= RP1_FSEL_COUNT && fsel != RP1_FSEL_NONE)
		return -EINVAL;

	rp1_set_fsel(pin, fsel);

	return 0;
}

static void rp1_pmx_gpio_disable_free(struct pinctrl_dev *pctldev,
				      struct pinctrl_gpio_range *range,
				      unsigned offset)
{
	(void)rp1_pmx_free(pctldev, offset);
}

static int rp1_pmx_gpio_set_direction(struct pinctrl_dev *pctldev,
				      struct pinctrl_gpio_range *range,
				      unsigned offset,
				      bool input)
{
	struct rp1_pin_info *pin = rp1_get_pin_pctl(pctldev, offset);

	rp1_set_dir(pin, input);
	rp1_set_fsel(pin, RP1_FSEL_GPIO);

	return 0;
}

static const struct pinmux_ops rp1_pmx_ops = {
	.free = rp1_pmx_free,
	.get_functions_count = rp1_pmx_get_functions_count,
	.get_function_name = rp1_pmx_get_function_name,
	.get_function_groups = rp1_pmx_get_function_groups,
	.set_mux = rp1_pmx_set,
	.gpio_disable_free = rp1_pmx_gpio_disable_free,
	.gpio_set_direction = rp1_pmx_gpio_set_direction,
};

static void rp1_pull_config_set(struct rp1_pin_info *pin, unsigned int arg)
{
	u32 padctrl = readl(pin->pad);

	FLD_SET(padctrl, RP1_PAD_PULL, arg & 0x3);

	writel(padctrl, pin->pad);
}

/* Generic pinconf methods */

static int rp1_pinconf_set(struct pinctrl_dev *pctldev, unsigned int offset,
			   unsigned long *configs, unsigned int num_configs)
{
	struct rp1_pin_info *pin = rp1_get_pin_pctl(pctldev, offset);
	u32 param, arg;
	int i;

	if (!pin)
		return -EINVAL;

	for (i = 0; i < num_configs; i++) {
		param = pinconf_to_config_param(configs[i]);
		arg = pinconf_to_config_argument(configs[i]);

		switch (param) {
		case PIN_CONFIG_BIAS_DISABLE:
			rp1_pull_config_set(pin, RP1_PUD_OFF);
			break;

		case PIN_CONFIG_BIAS_PULL_DOWN:
			rp1_pull_config_set(pin, RP1_PUD_DOWN);
			break;

		case PIN_CONFIG_BIAS_PULL_UP:
			rp1_pull_config_set(pin, RP1_PUD_UP);
			break;

		case PIN_CONFIG_INPUT_ENABLE:
			rp1_input_enable(pin, arg);
			break;

		case PIN_CONFIG_OUTPUT_ENABLE:
			rp1_output_enable(pin, arg);
			break;

		case PIN_CONFIG_OUTPUT:
			rp1_set_value(pin, arg);
			rp1_set_dir(pin, RP1_DIR_OUTPUT);
			rp1_set_fsel(pin, RP1_FSEL_GPIO);
			break;

		case PIN_CONFIG_INPUT_SCHMITT_ENABLE:
			rp1_pad_update(pin, RP1_PAD_SCHMITT_MASK,
				       arg ? RP1_PAD_SCHMITT_MASK : 0);
			break;

		case PIN_CONFIG_SLEW_RATE:
			rp1_pad_update(pin, RP1_PAD_SLEWFAST_MASK,
				       arg ? RP1_PAD_SLEWFAST_MASK : 0);
			break;

		case PIN_CONFIG_DRIVE_STRENGTH:
			switch (arg) {
			case 2:
				arg = RP1_PAD_DRIVE_2MA;
				break;
			case 4:
				arg = RP1_PAD_DRIVE_4MA;
				break;
			case 8:
				arg = RP1_PAD_DRIVE_8MA;
				break;
			case 12:
				arg = RP1_PAD_DRIVE_12MA;
				break;
			default:
				return -ENOTSUPP;
			}
			rp1_pad_update(pin, RP1_PAD_DRIVE_MASK, arg);
			break;

		default:
			return -ENOTSUPP;

		} /* switch param type */
	} /* for each config */

	return 0;
}

static int rp1_pinconf_get(struct pinctrl_dev *pctldev, unsigned offset,
			   unsigned long *config)
{
	struct rp1_pin_info *pin = rp1_get_pin_pctl(pctldev, offset);
	enum pin_config_param param = pinconf_to_config_param(*config);
	u32 padctrl;
	u32 arg;

	if (!pin)
		return -EINVAL;

	padctrl = readl(pin->pad);

	switch (param) {
	case PIN_CONFIG_INPUT_ENABLE:
		arg = !!(padctrl & RP1_PAD_IN_ENABLE_MASK);
		break;
	case PIN_CONFIG_OUTPUT_ENABLE:
		arg = !(padctrl & RP1_PAD_OUT_DISABLE_MASK);
		break;
	case PIN_CONFIG_INPUT_SCHMITT_ENABLE:
		arg = !!(padctrl & RP1_PAD_SCHMITT_MASK);
		break;
	case PIN_CONFIG_SLEW_RATE:
		arg = !!(padctrl & RP1_PAD_SLEWFAST_MASK);
		break;
	case PIN_CONFIG_DRIVE_STRENGTH:
		switch (padctrl & RP1_PAD_DRIVE_MASK) {
		case RP1_PAD_DRIVE_2MA:
			arg = 2;
			break;
		case RP1_PAD_DRIVE_4MA:
			arg = 4;
			break;
		case RP1_PAD_DRIVE_8MA:
			arg = 8;
			break;
		case RP1_PAD_DRIVE_12MA:
			arg = 12;
			break;
		}
		break;
	case PIN_CONFIG_BIAS_DISABLE:
		arg = ((padctrl & RP1_PAD_PULL_MASK) == (RP1_PUD_OFF << RP1_PAD_PULL_LSB));
		break;
	case PIN_CONFIG_BIAS_PULL_DOWN:
		arg = ((padctrl & RP1_PAD_PULL_MASK) == (RP1_PUD_DOWN << RP1_PAD_PULL_LSB));
		break;

	case PIN_CONFIG_BIAS_PULL_UP:
		arg = ((padctrl & RP1_PAD_PULL_MASK) == (RP1_PUD_UP << RP1_PAD_PULL_LSB));
		break;
	default:
		return -ENOTSUPP;
	}

	*config = pinconf_to_config_packed(param, arg);

	return 0;
}

static const struct pinconf_ops rp1_pinconf_ops = {
	.is_generic = true,
	.pin_config_get = rp1_pinconf_get,
	.pin_config_set = rp1_pinconf_set,
};

static struct pinctrl_desc rp1_pinctrl_desc = {
	.name = MODULE_NAME,
	.pins = rp1_gpio_pins,
	.npins = ARRAY_SIZE(rp1_gpio_pins),
	.pctlops = &rp1_pctl_ops,
	.pmxops = &rp1_pmx_ops,
	.confops = &rp1_pinconf_ops,
	.owner = THIS_MODULE,
};

static struct pinctrl_gpio_range rp1_pinctrl_gpio_range = {
	.name = MODULE_NAME,
	.npins = RP1_NUM_GPIOS,
};

static const struct of_device_id rp1_pinctrl_match[] = {
	{
		.compatible = "raspberrypi,rp1-gpio",
		.data = &rp1_pinconf_ops,
	},
	{}
};

static inline void __iomem *devm_auto_iomap(struct platform_device *pdev,
					    unsigned int index)
{
	struct device *dev = &pdev->dev;
	struct device_node *np = dev->of_node;

	if (np)
		return devm_of_iomap(dev, np, (int)index, NULL);
	else
		return devm_platform_ioremap_resource(pdev, index);
}

static int rp1_pinctrl_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct device_node *np = dev->of_node;
	struct rp1_pinctrl *pc;
	struct gpio_irq_chip *girq;
	int err, i;

	BUILD_BUG_ON(ARRAY_SIZE(rp1_gpio_pins) != RP1_NUM_GPIOS);
	BUILD_BUG_ON(ARRAY_SIZE(rp1_gpio_groups) != RP1_NUM_GPIOS);

	pc = devm_kzalloc(dev, sizeof(*pc), GFP_KERNEL);
	if (!pc)
		return -ENOMEM;

	platform_set_drvdata(pdev, pc);
	pc->dev = dev;

	pc->gpio_base = devm_auto_iomap(pdev, 0);
	if (IS_ERR(pc->gpio_base)) {
		dev_err(dev, "could not get GPIO IO memory\n");
		return PTR_ERR(pc->gpio_base);
	}

	pc->rio_base = devm_auto_iomap(pdev, 1);
	if (IS_ERR(pc->rio_base)) {
		dev_err(dev, "could not get RIO IO memory\n");
		return PTR_ERR(pc->rio_base);
	}

	pc->pads_base = devm_auto_iomap(pdev, 2);
	if (IS_ERR(pc->pads_base)) {
		dev_err(dev, "could not get PADS IO memory\n");
		return PTR_ERR(pc->pads_base);
	}

	pc->gpio_chip = rp1_gpio_chip;
	pc->gpio_chip.parent = dev;

	for (i = 0; i < RP1_NUM_BANKS; i++) {
		const struct rp1_iobank_desc *bank = &rp1_iobanks[i];
		int j;

		for (j = 0; j < bank->num_gpios; j++) {
			struct rp1_pin_info *pin =
				&pc->pins[bank->min_gpio + j];

			pin->num = bank->min_gpio + j;
			pin->bank = i;
			pin->offset = j;

			pin->gpio = pc->gpio_base + bank->gpio_offset +
				    j * sizeof(u32) * 2;
			pin->inte = pc->gpio_base + bank->inte_offset;
			pin->ints = pc->gpio_base + bank->ints_offset;
			pin->rio  = pc->rio_base + bank->rio_offset;
			pin->pad  = pc->pads_base + bank->pads_offset +
				    j * sizeof(u32);
		}

		raw_spin_lock_init(&pc->irq_lock[i]);
	}

	pc->pctl_dev = devm_pinctrl_register(dev, &rp1_pinctrl_desc, pc);
	if (IS_ERR(pc->pctl_dev))
		return PTR_ERR(pc->pctl_dev);

	girq = &pc->gpio_chip.irq;
	girq->chip = &rp1_gpio_irq_chip;
	girq->parent_handler = rp1_gpio_irq_handler;
	girq->num_parents = RP1_NUM_BANKS;
	girq->parents = pc->irq;

	/*
	 * Use the same handler for all groups: this is necessary
	 * since we use one gpiochip to cover all lines - the
	 * irq handler then needs to figure out which group and
	 * bank that was firing the IRQ and look up the per-group
	 * and bank data.
	 */
	for (i = 0; i < RP1_NUM_BANKS; i++) {
		pc->irq[i] = irq_of_parse_and_map(np, i);
		if (!pc->irq[i]) {
			girq->num_parents = i;
			break;
		}
	}

	girq->default_type = IRQ_TYPE_NONE;
	girq->handler = handle_level_irq;

	err = devm_gpiochip_add_data(dev, &pc->gpio_chip, pc);
	if (err) {
		dev_err(dev, "could not add GPIO chip\n");
		return err;
	}

	pc->gpio_range = rp1_pinctrl_gpio_range;
	pc->gpio_range.base = pc->gpio_chip.base;
	pc->gpio_range.gc = &pc->gpio_chip;
	pinctrl_add_gpio_range(pc->pctl_dev, &pc->gpio_range);

	return 0;
}

static struct platform_driver rp1_pinctrl_driver = {
	.probe = rp1_pinctrl_probe,
	.driver = {
		.name = MODULE_NAME,
		.of_match_table = rp1_pinctrl_match,
		.suppress_bind_attrs = true,
	},
};
builtin_platform_driver(rp1_pinctrl_driver);
