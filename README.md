# se09-docs

This repository contains all information about my IoT project for the SE09 module. The project is a base setup for an IoT application where users can control their smart devices via an smartphone app. Furthermore all logs/events from each IoT device are stored into a database.

## List of repos
- [user-service](https://github.com/henrikengelbrink/se09-user-service)
- [cert-service](https://github.com/henrikengelbrink/se09-cert-service)
- [device-service](https://github.com/henrikengelbrink/se09-device-service)
- [infrastructure](https://github.com/henrikengelbrink/se09_infrastructure)
- [user-app](https://github.com/henrikengelbrink/se09-user-app)
- [docker-images](https://github.com/henrikengelbrink/se09-docker-images)
- [hibp-service](https://github.com/henrikengelbrink/se09-hibp-check)
- [iot-device](https://github.com/henrikengelbrink/se09-iot-device)


## Architecture

![architecture.png](architecture.png "Architecture")


## Threat modelling

<iframe class="airtable-embed" src="https://airtable.com/embed/shr0tufoYRPPDTZJf?backgroundColor=red&viewControls=on" frameborder="0" onmousewheel="" width="100%" height="533" style="background: transparent; border: 1px solid #ccc;"></iframe>


# Kubernetes security

## Network policies

## Pod security policies



# Network security

## Ory Oathkeeper gateway

## Ambassador with TLS

## VPN to restrict access

## Database/Cluster limits



# IoT security

## MQTT broker

## Vault PKI

## Encrypted firmware



# Application security

##  OAuth 2.0 Authorization Code Flow with PKSE

##  Ory Hydra + user services for tokens

##  Authentification through Oathkeeper & Hydra

##  Authorization still done in application (Ory Keto for ACL's in the future)

##  bcrypt for salted and encrypted passwords

##  SQL injections

##  CORS



# Database security

##  Restrict access by IP and user permissions (least priviledge)

##  Backups/Recovery

##  Fallback during outtages



# Monitoring

## Sentry for crash reporting

##  Collect logs with the Elastic stack

##  Collect metrics with Prometheus

##  Auditing for PostgreSQL

