#!/usr/bin/env python3

from aws_cdk import core

from analytics.iot_analytics_es_stack import IotAnalyticsEsStack

app = core.App()

project_name = 'power-transformers-telemetry'

iot_analytics = IotAnalyticsEsStack(app, "iot-analytics-es", {'projectName': project_name})

app.synth()
