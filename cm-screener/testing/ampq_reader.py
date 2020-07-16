#!/usr/bin/env python
import pika

connection = pika.BlockingConnection(pika.ConnectionParameters('marri.cs.usyd.edu.au'))
channel = connection.channel()

channel.queue_declare(queue='detector')


def callback(ch, method, properties, body):
    print(" [x] Received correlation ID %s" % properties.correlation_id)
    ch.basic_ack(delivery_tag = method.delivery_tag)


channel.basic_consume(callback, queue='detector')

print(' [*] Waiting for messages. To exit press CTRL+C')
channel.start_consuming()
