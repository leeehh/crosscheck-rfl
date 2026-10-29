// SPDX-License-Identifier: GPL-2.0

#include <linux/err.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/iio/buffer.h>
#include <linux/iio/iio.h>
#include <linux/iio/trigger.h>
#include <linux/iio/trigger_consumer.h>
#include <linux/iio/triggered_buffer.h>
#include <linux/slab.h>

struct iio_dev *rust_helper_iio_devm_device_alloc(struct device *dev)
{
#ifdef CONFIG_IIO
	return devm_iio_device_alloc(dev, 0);
#else
	return ERR_PTR(-ENODEV);
#endif
}

int rust_helper_iio_devm_device_register(struct device *dev,
					 struct iio_dev *indio_dev)
{
#ifdef CONFIG_IIO
	return __devm_iio_device_register(dev, indio_dev, THIS_MODULE);
#else
	return -ENODEV;
#endif
}

int rust_helper_iio_device_id_safe(struct iio_dev *indio_dev)
{
#ifdef CONFIG_IIO
	return iio_device_id(indio_dev);
#else
	return -ENODEV;
#endif
}

void rust_helper_iio_device_set_drvdata(struct iio_dev *indio_dev, void *data)
{
#ifdef CONFIG_IIO
	iio_device_set_drvdata(indio_dev, data);
#endif
}

void *rust_helper_iio_device_get_drvdata(const struct iio_dev *indio_dev)
{
#ifdef CONFIG_IIO
	return iio_device_get_drvdata(indio_dev);
#else
	return NULL;
#endif
}

bool rust_helper_iio_device_claim_direct(struct iio_dev *indio_dev)
{
#ifdef CONFIG_IIO
	return iio_device_claim_direct(indio_dev);
#else
	return false;
#endif
}

void rust_helper_iio_device_release_direct(struct iio_dev *indio_dev)
{
#ifdef CONFIG_IIO
	iio_device_release_direct(indio_dev);
#endif
}

s64 rust_helper_iio_time_ns(const struct iio_dev *indio_dev)
{
#ifdef CONFIG_IIO
	return iio_get_time_ns(indio_dev);
#else
	return 0;
#endif
}

int rust_helper_iio_push_to_buffers_with_ts(struct iio_dev *indio_dev,
					    const void *data,
					    size_t data_size,
					    s64 timestamp)
{
#ifdef CONFIG_IIO
	return iio_push_to_buffers_with_ts_unaligned(indio_dev, data,
						     data_size, timestamp);
#else
	return -ENODEV;
#endif
}

int rust_helper_iio_devm_triggered_buffer_setup(
	struct device *dev, struct iio_dev *indio_dev,
	irqreturn_t (*handler)(int irq, void *p),
	irqreturn_t (*thread)(int irq, void *p))
{
#ifdef CONFIG_IIO
	return devm_iio_triggered_buffer_setup_ext(dev, indio_dev, handler,
						   thread,
						   IIO_BUFFER_DIRECTION_IN,
						   NULL, NULL);
#else
	return -ENODEV;
#endif
}

void rust_helper_iio_notify_trigger_done(struct iio_dev *indio_dev)
{
#if defined(CONFIG_IIO) && defined(CONFIG_IIO_TRIGGER)
	if (indio_dev->trig)
		iio_trigger_notify_done(indio_dev->trig);
#endif
}

struct iio_trigger *rust_helper_iio_devm_trigger_alloc(struct device *dev,
						       const char *name)
{
#if defined(CONFIG_IIO) && defined(CONFIG_IIO_TRIGGER)
	return __devm_iio_trigger_alloc(dev, THIS_MODULE, "%s", name);
#else
	return ERR_PTR(-ENODEV);
#endif
}

int rust_helper_iio_trigger_set_ops(
	struct device *dev, struct iio_trigger *trig,
	int (*set_trigger_state)(struct iio_trigger *trig, bool state))
{
#if defined(CONFIG_IIO) && defined(CONFIG_IIO_TRIGGER)
	struct iio_trigger_ops *ops;

	if (!trig || !set_trigger_state)
		return -EINVAL;

	ops = devm_kzalloc(dev, sizeof(*ops), GFP_KERNEL);
	if (!ops)
		return -ENOMEM;

	ops->set_trigger_state = set_trigger_state;
	trig->ops = ops;
	return 0;
#else
	return -ENODEV;
#endif
}

void rust_helper_iio_trigger_set_drvdata(struct iio_trigger *trig,
					 void *data)
{
#if defined(CONFIG_IIO) && defined(CONFIG_IIO_TRIGGER)
	iio_trigger_set_drvdata(trig, data);
#endif
}

void *rust_helper_iio_trigger_get_drvdata(struct iio_trigger *trig)
{
#if defined(CONFIG_IIO) && defined(CONFIG_IIO_TRIGGER)
	return iio_trigger_get_drvdata(trig);
#else
	return NULL;
#endif
}

int rust_helper_iio_devm_trigger_register(struct device *dev,
					  struct iio_trigger *trig)
{
#if defined(CONFIG_IIO) && defined(CONFIG_IIO_TRIGGER)
	return devm_iio_trigger_register(dev, trig);
#else
	return -ENODEV;
#endif
}

int rust_helper_iio_device_set_trigger(struct iio_dev *indio_dev,
				       struct iio_trigger *trig)
{
#if defined(CONFIG_IIO) && defined(CONFIG_IIO_TRIGGER)
	if (!indio_dev || !trig)
		return -EINVAL;

	indio_dev->trig = iio_trigger_get(trig);
	return 0;
#else
	return -ENODEV;
#endif
}

int rust_helper_iio_devm_request_trigger_data_rdy_irq(
	struct device *dev, unsigned int irq, unsigned long flags,
	const char *name, struct iio_trigger *trig)
{
#if defined(CONFIG_IIO) && defined(CONFIG_IIO_TRIGGER)
	if (!trig)
		return -EINVAL;

	return devm_request_threaded_irq(dev, irq,
					 iio_trigger_generic_data_rdy_poll,
					 NULL, flags, name, trig);
#else
	return -ENODEV;
#endif
}
