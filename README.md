# ids-tools

![CI](https://github.com/jzalger/ids-tools/workflows/CI/badge.svg?branch=dev)
![GitHub](https://img.shields.io/github/license/jzalger/ids-tools)
![GitHub Pipenv locked Python version (branch)](https://img.shields.io/github/pipenv/locked/python-version/jzalger/ids-tools/dev)
[![codecov](https://codecov.io/gh/jzalger/ids-tools/branch/dev/graph/badge.svg)](https://codecov.io/gh/jzalger/ids-tools)

This project provides a set of simple and lightweight logging and analysis utilities for the [Suricata](https://suricata-ids.org) network intrusion detection system (IDS). With ids-tools you can monitor your suricate json logs for events and alerts, log them to a Postgres database and perform automated location and IP or domain reputation inspection.

# Main Dependencies
Most of the project uses the standard Python library or common dependencies. However for the full stack experience, the following services are used to enrich event data or to enhance visualization.

1. [Maxmind GeoIP](https://maxmind.com/geoip) is used for geolocating logged IP addresses. Although an account is needed, an offline database can be downloaded avoiding constant API calls. A lower precision database is available at no cost.

2. [API Void](https://apivoid.com) is used for reputation analysis of suspicious events flagged by Suricata. Although this is a paid service, their prices are very competitive. They offer a free starting set of credits to test the service. For small networks, this can offer months of operation at no cost. To reduce the cost, apivoid queries are cached to avoid multiple lookups resulting from a flood of events.

3. [PostgreSQL](https://postgresql.org) is currently the only supported database backend. The JSONB type format in Postgresql provides a simple and very flexible way of managing semi-structured JSON events. It also has native support in Grafana for simple visualization.

4. [Grafana](https://grafana.com) is a visualization platform used to build a comprehensive network security dashboard.

# Project Development Workflow
The toolsuite is developed in Python and leverages Github actions for CI/CD. Pytest is used for unittests and CodeCov for coverage. Environments and deployent is managed with Pipenv.
