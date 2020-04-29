# se09-docs

This repository contains all information about my IoT project for the SE09 module. The project is a base setup for an IoT application where users can control their smart devices via smartphone app. Furthermore all logs/events from each IoT device should be stored into a database. A user can signup & login with the iOS app. After that he can claim an IoT device (washing machine) and configure it to connect to his local Wifi with the iOS app. After that his device is connected to the MQTT broker and he can change settings/read status of the device with his smartphone via MQTT.

In the future it should also be possible that service technicans can get access to data of the devices of their customers to remotely maintain them. This needs to be allowed explicitly by the owner of the device.

## List of repos
- [user-service](https://github.com/henrikengelbrink/se09-user-service)
- [cert-service](https://github.com/henrikengelbrink/se09-cert-service)
- [device-service](https://github.com/henrikengelbrink/se09-device-service)
- [infrastructure](https://github.com/henrikengelbrink/se09_infrastructure)
- [user-app](https://github.com/henrikengelbrink/se09-user-app)
- [docker-images](https://github.com/henrikengelbrink/se09-docker-images)
- [hibp-service](https://github.com/henrikengelbrink/se09-docker-images/tree/master/hibp)
- [iot-device](https://github.com/henrikengelbrink/se09-iot-device)

## Architecture

![architecture.png](assets/architecture.png "Architecture")

All the services are deployed and configured using Terraform scripts which makes it easy to reproduce the entire infrastrucure by simply running these scripts. In case of any problems you can easily spin up a totally fresh infrastructure within minutes and make this new system your production environment. The entire configuration is stored in Terraform Cloud, because the Terraform state files need to be synchronized between all the developers. These state files contain very sensitive data so they should never stay on the local machine and they are completely encrypted before they are uploaded to Terraform Cloud.

As part of the Terraform deployment I am also using the Helm package manager for Kubernetes. I am using the new Helm version 3 because this version does not need Tiller anymore. Tiller was always a security issue within the Kubernetes cluster because it required a very privilidged service account.

## Threat modelling

Table of all possible threats/attack vectors can be found here: https://airtable.com/embed/shr0tufoYRPPDTZJf?backgroundColor=red&viewControls=on

# 1. Kubernetes security
Kubernetes is the biggest container orchestration tool out there and it is used by a lot of companies from small startups to huge enterprises. Nevertheless, the default configuration of Kubernetes is pretty insecure. In the following I will explain possibilities to increase security of Kubernetes.


## 1.1 Network policies
By default all pods in a namespace can communicate with each other, independent whether it is necessary or not. This is a security issue, because if one pod is vulnerable, it is possible to access all other pods. If we limit the network capabilities to the minimum, we can reduce the impact of one vulnerable pod. I am blocking [all network connections between pods by default](https://github.com/henrikengelbrink/se09_infrastructure/blob/master/L2_InfrastructureConfig/k8s.tf#L11-L20) and enable them manually where it is necessary. The policies are automatically enforced by Kubernetes on layer 4 of the internal network. The entire configuration of all policies can be found [here](https://github.com/henrikengelbrink/se09_infrastructure/blob/master/L3_Services/network-policies.tf).

- https://medium.com/@reuvenharrison/an-introduction-to-kubernetes-network-policies-for-security-people-ba92dd4c809d

## 1.2 Pod security policies
By default all pods in a Kubernetes cluster can start with root priviledges and as root user, even if it is not neccessary for these pods. If one of these pods is vulnerable, the attacker can get access to the entire Kubernetes cluster. To prevent this, it is possible to define pod security policies for a Kubernetes cluster. These policies define some rules for pods which are started in the cluster, for example it is possible to define that pods cannot start in priviledged mode or as root user. I defined a [simple pod security policy](https://github.com/henrikengelbrink/se09_infrastructure/blob/master/L3_Services/crds/psd.yml) which is preventing pods starting with priviledges or a root user. This is only a simple starting point and there are a lot of possible configurations available, but for the beginning this simple policy already helps to make the cluster more secure.

- https://banzaicloud.com/blog/pod-security-policy/
- https://docs.bitnami.com/kubernetes/how-to/secure-kubernetes-cluster-psp/

## 1.3 Secret management
All the secrets/certificates that needs to be injected in some backend services are managed by Hashicorp Vault. Hashicorp Vault is a tool which is basically meant to store and protect sensitive data. All the secrets are encrypted and stored by Vault and automatically injected into the corresponding services by an agent which needs to be defined in the YML file of the deployment, [like in this config file for the VerneMQ MQTT broker](https://github.com/henrikengelbrink/se09_infrastructure/blob/master/L3_Services/vernemq.tf#L56-L73). 

Hashicorp Vault itself can be sealed/unsealed. In the sealed mode it is not possible to get any data from it. The unseal process is based on Shamir's Secret Sharing algorithm. The basic idea of this algorithm is to split an unseal secret into multple pieces and to unseal Vault you need for example three of five of these keys. I am using the automatic unseal feature of Vault together with the Google Cloud Key Management Service where these additional keys are stored into Google Cloud and the seal/unseal process is automatically done by Vault.

- https://www.vaultproject.io/docs/concepts/seal
- https://learn.hashicorp.com/vault/operations/autounseal-gcp-kms
- https://quarkus.io/guides/vault

## 1.4 Mutual TLS
By default all the traffic between pods/services is not encrypted. Services meshes are one easy possibility to implement mutual TLS between all services. In general services meshes are adding another layer on top of Kubernetes. There are three bigger solutions for Kubernetes: [Linkerd](https://linkerd.io/), [Consul](https://www.consul.io/) and [Istio](https://istio.io/). All of them offer the possibility to implement mutual TLS, but I decided to use Istio because it also offers other functionalities which will be presented later in this document. 

Setting up Istio to use mutual TLS is pretty easy, you only have to install Istio to the cluster and enable mutual TLS in the config. Istio is setting up Envoy proxies in front of every service and it automatically creates certificates which will be used to terminate the traffic between services within each Envoy proxy.

<br/><br/>

# 2. Network security

This image shows the network flow of all incoming connections to the Kubernetes cluster. Each of these components will be described in the next sections.
![Network_flow.png](assets/Network_flow.png "Network inbound flow")

## 2.1 Cloud Firewall
The infrastructure of this project is running on DigitalOcean. Every managed Kubernetes cluster at DigitalOcean comes automatically with an preconfigured Cloud Firewall which automatically blocks traffic for all ports to the Droplets (Nodes/VM's) except the ports which are necessary to run Kubernetes. The firewall is configured in a way that it only allows traffic which comes from the internal private cloud network of all nodes of the cluster. This cloud firewall prevents hacker to directly access any node of the Kubernetes cluster. All incoming traffic from outside is routed through the load balancer which is connected to the Ambassador Edge Stack service any Ory Oathkeeper. I am going to describe these two services more detailed in the next two sections.

## 2.2 Ambassador Edge Stack with TLS
The Ambassador Edge Stack is one of many possible solutions for Kubernetes API gateways. Ambassador is a software which is provisioned via Helm chart into the Kubernetes cluster. Ambassador is working as a Kubernetes ingress, this means it define all possible routes into the cluster itself. Internally the managed DigitalOcean cluster spins up a load balancer at DigitalOcean which recievces all the traffic and routes it to the Ambassador service. Ambassador is routing the requests depending on the specific sub-domain the the corresponding service in the Kuberentes cluster. 

Furthemore Ambassador is also terminating TLS. Therefore it is using the cert-manager and Let's Enrypt to autmatically provision and update TLS certificates for all domains. Through TLS the entire communication via HTTPS between the clients and the server is encrypted.

## 2.3 Ory Oathkeeper
Ory Oathkeeper is a cloud-native identity & access proxy which is written in Go and completely open source. All incoming API requests for the backend (*https://api.engelbrink.dev* ) are routed from Ambassador Edge Stack to Ory Oathkeeper. Based on a [JSON configuration file](https://github.com/henrikengelbrink/se09_infrastructure/blob/master/L3_Services/oathkeeper-rules.json) Ory Oathkeeper routes the traffic to the corresponding service. The configuration file defines each route and furthermore you can configure authentication, authorization and mutators for each route. 

By using Ory Oathkeeper there is only a single point where all the API endpoints are made public and secure. Every new endpoint needs to be explicitly defined in the configuration which eliminates the danger of publishing endpoint accidentially. Furthermore the authentication and authorization only needs to be implemented in Ory Oathkeeper and not in every single service. This reduces complexity and makes it easier to keep an overview of the entire backend and all public routes. The points authentication and authorization will be explained under *Application security* in a more detailed way.

## 2.4 VPN to restrict access (DB/Kubernetes)
Some endpoints and services should not be available for everyone in public, for example the endpoint where we create new IoT devices in our device-service or the access the PostgreSQL cluster. For these use-cases I have setup an OpenVPN server at DigitalOcean and the endpoint for creating devices (tbd.) and the [PostgreSQL cluster](https://github.com/henrikengelbrink/se09_infrastructure/blob/master/L2_InfrastructureConfig/db.tf#L29-L33) are only accessible through the VPN. This reduces the risk of unauthorized access to these resources.

## 2.5 DNS security / TLS

The Domain Name System (DNS) is one important part of the internet/networking because it translates specific domains that users enter into their browsers into specific IP addresses of a server that is running the application the user wants to access. In order to increase the DNS security I have implemented and configured the following things:

**Add CAA record**
CAA (Certificate Authority Authorization) records specify which certificate authorities are permitted to issue certificates for a specific domain. They help to reduce the risk of unintended certificate mis-issue.

**Only TLS v1.2 and v1.3**
The Ambassador Edge Stack only supports TLS v1.2 and TLS v1.3 and older versions are not supported, because they are not considered secure enough anymore.

**Specific cipher suites**
In general cipher suites describe which algorithms are used to encrypt network communication between clients. In TLS version up to 1.2 these algorithm sets were defined for key exchange, block cipher and message authentication. In TLS 1.3 a lot of legacy algorithms were dropped out and the strucutre changed a little bit which results in an even more secure protocol. By default, the Ambassador Edge Stack supports a lot of cipher suites including some which are considered insecure. In order to increase the security I only allow one of the following cipher suites because they are acknowledged as secure by SSLLabs(Qualys):

TLS 1.2
- TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
- TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
- TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

TLS 1.3
- TLS_AES_128_GCM_SHA256
- TLS_AES_256_GCM_SHA384
- TLS_CHACHA20_POLY1305_SHA256

### 2.5.4 HTTP Strict Transport Security (HSTS)
HSTS is a mechanism which helps to mitigate man-in-the-middle attacks in network communication. HSTS means that the server sends an additional header to the client which inform the client that only encrypted HTTPS connections are allowed.

### 2.5.5 Domain Name System Security Extensions (DNSSEC)
DNSSEC is a list of different standards which helps to increase the DNS security by enusring authenticity and integrity of the DNS sources. Unfortuentely DigitalOcean does not provide these functionalities, so if this would be an obligatory measure for the project it is necessary to change the cloud provider.

<br>
All of these steps helped me to increase the DNS/TLS security which results in a A+ ranking at SSLLabs:

![ssl.png](assets/ssl.png "SSLLabs result")

- https://www.thesslstore.com/blog/cipher-suites-algorithms-security-settings/
- https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices

<br/><br/>

# 3. Application security

One important aspect of an IT project is the application security because at this point a lot of security principales and measures from different branches (database security, network security, etc) are coming together and every small bug/misconfiguration in the application can cause major security issues.

## 3.1 Authentication through Oathkeeper & Hydra

The authentication for the system is based on two components of the open source project Ory where I am using Ory Hydra to issue access tokens based on the OAuth2 protocol and Ory Oathkeeper which validates these tokens before requests are routed to a specific service. I am going to describe all the parts and connections of this complex system in the next sections.

### 3.1.1 OAuth2.0 protocol (Authorization Code Flow with PKSE for iOS)
Authentication for the entire system is based on the OAuth2 protocol. The OAuth2 protocol offers different types of grants which deliver the access token to the client. Depending on the client type there are different ways to handle to access token exchange. I decided to use the Authorization Code Flow with PKSE because the user is interacting via the native iOS app and this flow is the most secure for a native smartphone app. 

During the Authorization Code Flow, the client is generating a secure random code verifier and a hashed code challenge. The code challenge is put into an request which is send to the authentication server to initialze the authentication session. The authentication server persists the code challenge, the requested audience and the client identifier for the life time of the login session. After that, the authentication server redirects the user an web-based user interface where he can enter his credentials. By submitting the login form in the UI, the user sends the entered credentials back to the authentication server where the credentials are verified. If the credentials are valid, the user is redirected to the redirect uri with the authroization code in the URL. The client app uses this authorization code and the code verifier to request the tokens from the authentication server. These tokens can then be used to access some API's.

The authentication flow I am using at the moment is not entirely OAuth2 compliant because I am skipping the consent provider flow, where the users is authorizing each application specifc access to his data. I have done this, because in the beginning it is only my service who is accessing the data and if a user want to signup/login into my application, he already showed the intention to provide his data. In the future I am planning to integrate with other services or give access to other third parties and in this case the consent provider needs to be included into the flow.

### 3.1.2 Ory Hydra
The entire OAuth2 is pretty complex and implementing every detail by yourself requires a lot of knowledge and time and even the smallest problem can cause huge vulnerability issues. For this reason, I decided to use an already existing solution. There are a lot of possibilites out there, e.g. SaaS solutions like Auth0 and Okta or open source projects like KeyCloak or Ory Hydra. I decided not to choose a proprietary SaaS because this results in a vendor lock-in. 

During my research, I found some open source projects which are offering solutions for Identity and Access Management (IAM) but most of them were complex to configure and setup and others were not entirely cloud native. Fortunately, I have found the [Ory project](https://www.ory.sh/) and they offer four different solutions in the space of IAM which are easy to configure and completely cloud native. I have decided to go with Ory Hydra which is a OAuth2 and OpenID Connect server for secure access to applications and API's. All the heavy work like verifiying codes/challenges and issuing tokens are done by Hydra, only the user management itself needs to be done by yourself. They are also offering a solution for this, Ory Kratos, but it was not out of beta when I started the project, so I decided to implement the user management by myself.

### 3.1.3 User-service
Thre user-service itself is a Kotlin application using the Micronaut framework. All the user data is stored in a Postgres database. The user-service has two major functionalities. The first part is serving the HTML files which are shown to the user during registration/login. The second part are the logic to store users and their credentials encrypted in the database and verify user-entered credentials during the login. Therefore, the user-service is closely connected to the Hydra service and during every signup/login there is a lot of communication between Ory Hydra and the user-service.

### 3.1.4 Ory Oathkeeper
Every incoming request to any API is going through the Ory Oathkeeper proxy. Every API route is defined in the [JSON configuration file](https://github.com/henrikengelbrink/se09_infrastructure/blob/master/L3_Services/oathkeeper-rules.json). If a specific route is only accessible for authenticated users, Ory Oathkeeper checks whether the request contains the authorization header with the Token and if this is the case, it validates the token by calling the introspect endpoint of Ory Hydra. This functionality is easyily configureable in the config file, which is a huge benefit of the Ory project.

<br/>

**Detailed UML sequence diagram of the authentication flow:**
![AuthFlow_UML.png](assets/AuthFlow_UML.png "Authentication flow")

## 3.2 Authorization
Besides authentication, authorization is a important point in application security. Authentication is used to make sure that a requesting user is known and validated by my system, whereas authorization is checking whether the user who requests some resource is allowed to access this specific resource. It is a common problem in applications, that it is possible to get access to resources of other users in cause of bugs in the authorization process.

At the moment I have implemented the authorization logic into each service I have implemented. For example if an authenticated user is requesting data for a specific device at */devices/device-id-abc-123*, I am explicitly checking whether the user is the owner of the device. By implementing this for every single endpoint explicitly, it is very easy to make mistakes and forget about this, which immediately results in an vulnerability. Writing tests can help to prevent deploying these vulnerabilities to a production system, but it is still possible.

A better solution would be to use a specific access control server which is connected to the Ory Oathkeeper proxy to automatically check these things for every incoming request. This will result into one single service where all the configurations need to be implemented. The Ory project is offering a service called Keto for this, but it is still in beta status and a lot of functionalities are still missing, but in the future this would be the way I would handle authorization. Keto is supposed to use access control patterns like Role-Based-Access-Control (RBAC), Attribute-Based-Access-Control (ABAC) or Access-Control-Lists (ACL).

## 3.3 Bcrypt for salted and hashed passwords
It is a common problem that there are still applications and services which store password into the database in plaintext which means as soon a hacker get access to a database, he is able to read and use all the user passwords. Even if this is a problem since the beginning of the internet and every developer should know about this, you can read about data leaks with plaintext passwords weekly.

I deciced to use the bcrypt algorithm to hash and salt the passwords I am storing in the database with my user-service. Bcrypt is using a random and securely generated Salt which is added to the hash of the acutal password. This makes it impossible for the attacker to use Rainbow/lookup tables to crack the password. Furthemore bcrypt is using an algorithm which makes the hash-function slower. This makes brute forcing millions of passwords nearly impossible (until the hacker has a lot of computational power) because it would take too much time.

- https://auth0.com/blog/hashing-in-action-understanding-bcrypt/

## 3.4 HaveIBeenPwned service
The developer Troy Hunt started a project called [*HaveIBeenPwned*(https://haveibeenpwned.com/) where he basicaly collects data from password leaks. At the moment the project contains over 550 million leaked passwords. It is common that hacker are using data from prior leaks and use them to get access in other services with this data or they are using these very common passwords to brute force other services. As a developer you can use the data of *HaveIBeenPwned* and check every new user password against this data collection and if the new password of the user appears in *HaveIBeenPwned* you can tell him to use another password.

I have downloaded the entire HIBP data as a CSV file, created an bloom filter out of it and implemented a REST API which uses this bloom filter to check if a password was already leaked. On every new user registration, [the user-service is checking](https://github.com/henrikengelbrink/se09-user-service/blob/master/src/main/kotlin/se09/user/service/services/UserService.kt#L29-L31) the password of the user with the [hibp-service](https://github.com/henrikengelbrink/se09-docker-images/tree/master/hibp).

- https://haveibeenpwned.com/
- https://github.com/willf/bloom
- https://github.com/adewes/have-i-been-bloomed/blob/master/Makefile
- https://github.com/adewes/bloom

## 3.5 SQL injections
SQL injections are nothing I have to actively care about in this project because I am using an ORM in all services that are using some SQL. I am not writing any SQL statements because the ORM is building all the queries and it also takes care about escaping queries to prevent SQL injections.

- https://owasp.org/www-community/attacks/SQL_Injection

## 3.6 Cross-Origin Resource Sharing (CORS)
CORS is way to restrict which web services with a different host can access your backend. By default, a web app like `https://example-a.com` can not reach a backend `https://api-b.com` because of the same origin policy which is applied. In order to allow a request like this, you have to define specific CORS header in the backend so that the web app is able to request data from the backend. At the moment I have only implemented the iOS app which is communicating to my backend services and there is no webapp which is running in a browser, so there is no need to define these CORS configurations. If this is going to change in the future, I would add these configurations in the Ambassador Edge Stack configuration. In this configuration I can define headers which should be added to each response which is going back to the client from the backend.

- https://auth0.com/blog/cors-tutorial-a-guide-to-cross-origin-resource-sharing/
- https://www.codecademy.com/articles/what-is-cors

## 3.7 Cross-Site-Request-Forgery (CSRF)
As soon as the user logged into you application, you can store the login state into a cookie. This cookie is send with every request to the backend in order to authenticate the user so that he only needs to login once for a specific time range. This can be abused by an attacker. The attacker can implement his own site where he is executing an unintended request  from his site to your backend. This happens without the user knowing about it and because of the existing cookie, the request can potentially result in some malicious/unwanted changes in the backend. To prevent this kind of attack, you can add a CSRF token to every webpage which is additionally send with each request to the backend an then validated in the backend.

At the moment I am only using the iOS application and the internal UIWebView/WKWebView I am using does not store any cookies and is totally sandboxed, so it is not possible that any third-party is executing unintended requests with some stored cookies.

- https://auth0.com/docs/protocols/oauth2/mitigate-csrf-attacks
- https://developers.shopware.com/developers-guide/csrf-protection

## 3.8 Cross-Site Scripting (XSS)
XSS attacks are based on the fact, that an attacker is able to inject malicious code into a web application by executing for example JavaScript from input fields. To prevent these kind of attackes it is necessary to validate and escape every user input to be sure that no injected code is executed. 

At the moment I am only using the iOS application and the login/register views are handled by the AppAuth framework. The AppAuth framework is the only possibility to open these pages and it is not necessary for an attacker to inject some malicious inputs.

- https://auth0.com/blog/developers-guide-to-common-vulnerabilities-and-how-to-prevent-them/#Cross-Site-Scripting--XSS-

<br/><br/>

# 4. IoT security

## 4.1 MQTT broker
The communication with the Iot devices is handled via the MQTT protocol. MQTT is a protocol which is based on clients that publish/subscribe for specific topics at the MQTT broker which is the central element of the MQTT system where all messages are processed. I am using the [VerneMQ](https://vernemq.com/) MQTT broker which is written in Erlang and completely open source.

For every new IoT device I am creating a certificate which is used to authenticate the client whenever he wants to connect to the broker. Furthermore, the client also needs to provide a valid password which is validated in the backend. When a new client connects to the MQTT broker, the broker is checking whether the client certificate is a valid certificate which matches the server certificate. This is handled on OSI layer 4. If the certificate is valid, the [broker sends a request](https://github.com/henrikengelbrink/se09_infrastructure/blob/master/L3_Services/vernemq.tf#L45-L46) to the cert-service. The [cert-service](https://github.com/henrikengelbrink/se09-cert-service/blob/master/src/main/kotlin/se09/cert/service/controller/VerneMQController.kt#L21-L42) uses the credentials and validates the login with the [device-service](https://github.com/henrikengelbrink/se09-cert-service/blob/master/src/main/kotlin/se09/cert/service/ws/DeviceWebService.kt#L18-L30).

The same procedure is also done for every publish/subscribe event. In this route, I am additionally checking whether the client is allowed to subscribe/publish to the specific login he tries to publish/subscribe. This prevents that an authenticated users can access the device of someone else without being allowed to do this.

![MQTT_Auth.png](assets/MQTT_Auth.png "MQTT Authentication flow")

- https://www.hivemq.com/blog/mqtt-security-fundamentals-wrap-up/
- https://docs.vernemq.com/plugindevelopment/webhookplugins

## 4.2 Vault PKI / Public-key cryptography
As described in the previous part, everty IoT device gets an certificate which is created in a backend service. The process of creating and signing all the certificates is very complex, so I decided to use an existing solution for this. Hashicorp Vault which I am already using for secret management in my Kubernetes cluster also offers the functionality of creating your own Public-Key-Infrastrucure (PKI). I have used this feature to setup my own PKI to handle the certificates for all the IoT devices. The certificates and keys are not stored in Vault, they are copied to the device and not persisted afterwards. The certificate for each device expires after one year and after that time, the certificate needs to be renewed. The new certificate will be updated by the device-service via the Over-the-Air-Update (OTA) with the firmware.

- https://learn.hashicorp.com/vault/secrets-management/sm-pki-engine
- https://www.hashicorp.com/blog/certificate-management-with-vault/
- https://kubernetes.io/docs/tasks/inject-data-application/distribute-credentials-secure/
- https://www.hashicorp.com/blog/injecting-vault-secrets-into-kubernetes-pods-via-a-sidecar/
- https://medium.com/@ScottAmyx/managed-pki-certificates-one-step-at-a-time-toward-securing-the-iot-8b4c539c8ec
- https://dev.to/v6/vault-pki-secrets-engine-with-intermediate-signing-authority-hap

## 4.3 IoT device
I decided to use the ESP32 with Mongoose OS for the IoT device. Mongoose OS is open source and it offers a lot of functionalities like OTA. The Over-the-Air-Updates are handled by the device-servie and whenever the device gets the message to update itself via MQTT, it is downloading the new firmware via a GET request from the device-service. 

Mongoose OS offers the functionality to encrypt the firmware and all other files on the device. This prevents attackers to reverse engineer the device or steal credentials like the MQTT certificates from the device or manipulate the device, for example during the shipping process. The encryption needs to be enabled via the Mongoose OS CLI which creates and secret key file which is necessary for all future firmware updates. I have unfortunately not implemented this at the moment, but the plan is to store all these encryption keys for each device in Hashicorp Vault where the device-service can access them for future firmware updates.

- https://mongoose-os.com/docs/mongoose-os/userguide/security.md
- https://www.nexusgroup.com/how-to-validate-certificates-in-iot-devices-5/

<br/><br/>

# 5. Mobile security

## 5.1 AppAuth
The entire authentication process with OAuth2/OpenID during login/registration in the iOS app is handled by the [AppAuth SDK](https://github.com/openid/AppAuth-iOS) which is offered by the [OpenID Foundation](https://openid.net/). I have not implemented anything of this by my own but I only stick to their SDK which seems the most secure solution because they are trusted and well known to be very good in OAuth2 and OpenID.

## 5.2 iOS keychain
All the tokens like access and refresh token which are requested from Ory Hydra to authenticate the user at my backend services are stored in the iOS keychain where they will be automatically encrypted by iOS itself. It is also not possible for other apps or attackers to access these credentials stored in the iOS keychain because every app is running in her own sandbox and there is no possibilty to reach credentials from another app from the keychain.

- https://developer.apple.com/documentation/security/keychain_services

<br/><br/>

# 6. Database security

## 6.1 Restrict access by IP and user permissions (least priviledge)
One easy approach to secure the Postgres cluster is simply to restrict the access to it. The first level of restriction is to block all requests to the database except for the IP address of the Kubernetes cluster. This can be done by the Digital Ocean [database firewall](https://github.com/henrikengelbrink/se09_infrastructure/blob/master/L2_InfrastructureConfig/db.tf#L26-L39).

Furthermore, each backend service which needs to store data in the Postgres cluster has his own database and his own user. This service-specific user has onlys access to the service-specific database. These users have full permissions to create and alter tables in their database because the services are handling all the migrations. In the future there might be some other services like analytics tools which needs access to specific databases. For each of these tools there needs to be an additional user created which has only read access on data in tables but have no permissions to change/drop schemas.

## 6.2 Backups/Disaster Recovery
I do not have to handle database backups manually because I am using the managed database instances at DigitalOcean and they are already automatically taking backups of the data. In case of any problems I have the option to restore the running instance to a specific point in time or fork the entire instance which means that I create a new instance which is mirroring the data from a specific point of time. 

These restoring steps become only necessary if DigitalOcean gets huge issue with their system, because every database cluster can have up to two additional standby nodes, which are constantly reading all the changes from the master's write ahead log. In case the master node has any issues or looses connection, one of the standby nodes will automatically take over as a fallback without nearly no downtime. 

In order to prevent entire dataloss if the datacenter gets critial issues, I could dump and mirror the data of my database to another cloud provider.

<br/><br/>

# 7. Monitoring

## 7.1 Sentry for crash reporting
Sentry is a SaaS tool which lets you easily collect all crashes of your application. I am only using it to collect exceptions of my backend services which are written in Kotlin, but they also offer SDK's for other languages and platforms, so it would be also possible to monitor the iOS application.

Setting up Sentry for the Kotlin based services is pretty easy, I only have to [include the SDK in the `build.gradle`](https://github.com/henrikengelbrink/se09-user-service/blob/master/build.gradle#L37) file and provide the [environment variable `SENTRY_DSN`](https://github.com/henrikengelbrink/se09_infrastructure/blob/master/L3_Services/user-service.tf#L74-L77) to authenticate the client. There are no further configurations necessary and every exception including the stacktrace will be automatically collected in their service. It is also possible to host the Sentry server in your own infrastructure but I am currently using their SaaS solution.

## 7.2 Application Performance Monitoring
Application Performance Monitoring enables you to track everything happening inside your service, for examples you can track every part of an incoming HTTP request of a REST API like receiving and parsing the request, handling the request, running queries to external databases and send the response to the client. For every of these steps you can monitor CPU and memory usage, the time it takes to compute or any other possible metric. APM offers a lot of possibilites to monitor the status of your application and to optimize it and find possible bottlenecks before they become critical for your user/system.

Unfortunately I did not found time to add this feature to my project, but there are SaaS solutions like DataDog or NewRelic available and by adding their agent to your services, it is pretty easy to use APM. Furthermore, Elastic, the company behind the Elastic Stack, also offers a open source solutions for this. Elastic APM can be used for free and is deployed in your own infrastrucutre or you can use their cloud service as well. Elastic APM requires a little bit more time to configure but it is cheaper and you own all the data.

## 7.3 Collect logs with the Elastic Stack
The Elastic Stack offers the possibility to collect all logs from different services running in the Kubernetes cluster at one single point. This is very helpful to see problems in advance and always get an overview of the status of the entire system. Furthermore, these logs can help to find useful data during the post-mortem of any (security) incident.

The Elastic Stack is [deployed into Kubernetes using the official Helm charts](https://github.com/henrikengelbrink/se09_infrastructure/blob/master/L3_Services/elastic.tf). It consists out of different services: Elasticsearch which is the database where the entire logs are stored, Filebeat which reads all the logs(log-files) from Kubernetes and pushes them into the Elasticsearch database, Metricbeat is collecting metrics of the Kubernetes cluster itself and Kibana offers the possibility to visualize all the gathered data to in different dashboards. Furthermore there are some additional services like alerting services which send SMS/Slack message for specific events or when specific thresholdes are passed.

By collecting all these logs it is for example possible to track all failed login attempts during a specific time period in order to recognize possible attacks against your system.

## 7.4 Collect metrics with Prometheus
[Prometheus](https://prometheus.io/) is a monitoring system and a timeseries database which is used to monitor system metrics over time. It was developed at SoundClound and is open sourced in the Cloud Native Foundation. During the last years it became a de-facto standard when it comes to monitor metrics of backend services, this is a reason why nearly all bigger services/tools are delivered with prometheus endpoints where prometheus can periodically scrape all the metrics.

Prometheus is automatically deployed with Istio and all Istio related metrics are automatically loaded into Prometheus. In the future I also want to put all the metrics of Ambassador, Ory Oathkeeper, Ory Hydra and VerneMQ into Prometheus. All the data which is scraped by Prometheus can be visualized with [Grafana](https://grafana.com/).

## 7.5 Traffic management with Kiali
[Kiali](https://kiali.io/) is a open source service mesh observability tool which gives you an overview of all services that are running in your cluster. Furthermore it is possible to visualize the connections between different services and how they are communicating with each other. There are plenty other useful functionalites in Kiali but I had no time to dig deeper into it. Kiali is also automatically deployed as a part of Istio.

## 7.6 Tracing with Jaeger
[Jaeger](https://www.jaegertracing.io/) is a open source distributed tracing tool which allows you to trace single requests between different microservices running in your backend. Tracing can be really helpful if you are trying to debug your system and want to find bugs or misconfigurations. I only used the base functionalities of Jaeger which were deployed and configured with the default Istio deployment and I did not had enough time to go deeper into Jaeger but it seems to be a very useful tool, espacially if you are running a lot of microservices in production.

## 7.7 Auditing for PostgreSQL
For debugging or incident investigation it can be really useful to get insights which queries are executed in your database. Furthermore, there are some legal regulations that forces you to run database audits like this where you can see who changed/accessed which data on which time. This can be either done via the application which is executing the queries or it is directly done by the database instance itself. In my case, I am only using the simple SQL audit log which is delivered with the managed database of DigitalOcean, but if I would going to run this project in production I would rather use a more advanced and configurable solution which is auditing the logs on application level.

<br/><br/>

# 8. Improvements for the future:

## 8.1 Cloud provider reliability
I deployed my entire infrastructure to the Frankfurt region of DigitalOcean. In case the entire datacenter goes down, my services will be probably offline. If I am running really critical services I would rather choose one of the big three cloud providers (AWD, GCP, Azure) because they are offering multiple zones per region, so even if one zone(datacenter) is going down, my infrastrucure in the other zones is still running. Furthermore they also offer multi-zone and multi-regional Kubernetes clusters which will also decrease the risk of having downtime.

## 8.2 Further improvments
- Container image scanning to prevent vulnerabilities within them
- 2FA with Authy from Twilio
