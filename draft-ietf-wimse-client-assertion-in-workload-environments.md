---
title: OAuth 2.0 Client Assertion in Workload Environments
abbrev: Workload Identity
docname:  draft-ietf-wimse-client-assertion-in-workload-environments-latest
category: info

ipr: trust200902
area: Security
workgroup: WIMSE
keyword: Internet-Draft

stand_alone: yes
pi:
  rfcedstyle: yes
  toc: yes
  tocindent: yes
  sortrefs: yes
  symrefs: yes
  strict: yes
  comments: yes
  inline: yes
  text-list-symbols: -o*+
  docmapping: yes

author:
 -
      ins: B. Hofmann
      name: Benedikt Hofmann
      email: hofmann.benedikt@siemens.com
      org: Siemens

 -
      ins: H. Tschofenig
      name: Hannes Tschofenig
      email: hannes.tschofenig@gmx.net
      org: Siemens

 -
      ins: E. Giordano
      name: Edoardo Giordano
      email: edoardo.giordano@nokia.com
      org: Nokia

 -
      ins: Y. Rosomakho
      name: Yaroslav Rosomakho
      email: yrosomakho@zscaler.com
      org: Zscaler

 -
      ins: A. Schwenkschuster
      name: Arndt Schwenkschuster
      email: arndts.ietf@gmail.com
      org: Microsoft

normative:
  RFC2119:
  RFC7521:
  RFC7523:
  RFC6749:
  RFC8174:
  RFC8414:
  RFC7519:
  RFC7517:
informative:
  OIDC:
     author:
        org: Sakimura, N., Bradley, J., Jones, M., de Medeiros, B., and C. Mortimore
     title: OpenID Connect Core 1.0 incorporating errata set 1
     target: https://openid.net/specs/openid-connect-core-1_0.html
     date: 8 November 2014
  KubernetesServiceAccount:
     title: Kubernetes Service Account
     target: https://kubernetes.io/docs/concepts/security/service-accounts/
     date: 10 May 2024
  TokenReviewV1:
     title: Kubernetes Token Review API V1
     target: https://kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-review-v1/
     date: 28 August 2024
  TokenRequestV1:
     title: Kubernetes Token Request API V1
     target: https://kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-request-v1/
     date: 28 August 2024


--- abstract

The use of the OAuth 2.0 framework for container orchestration systems poses a challenge as managing secrets, such as client_id and client_secret, can be complex and error-prone. Instead of manual provisioning these credentials the industry has moved to a federation-based approach where credentials of the underlying workload platform are used as assertions towards an OAuth authorization server leveraging the Client Assertion Flow {{RFC7521}}, in particular {{RFC7523}}.

This approach is seen in the industry across many workload environments, this document outlines common patterns and their use cases.

--- middle

# Introduction

Workloads often require access to external resources to perform their tasks. For example, access to a database, a web server or another workload. These resources are protected by an authorization server and can only be accessed with an access token. The challenge for workloads is to get this access token issued.

Traditionally, workloads can be provisioned with client secrets credentials and use the client_credential flow to retrieve an access token. This model comes with a set of challenges that make it insecure and high-maintaince. Client secrets need to be manually provisioned and rotated. They can be stolen and used by attackers to impersonate the workload.

A solution to this problem is to not provision secret material to the workload itself but use the workload platform to attest for that workload. Many workload platforms offer a credential, in most cases a JWT token. Signed by a platform-internal authorization server, this credential attests the workload and its attributes. Based on {{RFC7521}} and its JWT profile {{RFC7523}}, this credential can then be used as a client assertion towards a different authorization server.

# Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in
BCP 14 {{RFC2119}} {{RFC8174}} when, and only when, they appear in all
capitals, as shown here.

The terms 'workload' and 'container' are used interchangeably.

# OAuth Assertion in Workload Environments

## Overview

{{fig-overview}} illustrates a generic pattern that applies across all of the patterns described in {{patterns}}:

~~~ aasvg
 +----------------------------------------------------------+
 |                           External Authorization Domain  |
 |                                                          |
 | +-------------------------+     +--------------------+   |
 | |                         |     |                    |   |
 | |   Authorization Server  |     | Protected Resource |   |
 | |                         |     |                    |   |
 | +-------^---------+-------+     +----------^---------+   |
 +---------+---------+------------------------+-------------+
           |         |                        |
           |   3) access token           4) access
           |         |                        |
2) present assertion |                        |
           |         |     +------------------+
           |         |     |
 +---------+---------+-----+--------------------------------+
 |         |         |     |             Workload Platform  |
 |         |         |     |                                |
 |  +------+---------v-----+---+           +-------------+  |
 |  |                          |           | Credential  |  |
 |  |        Workload          +-----------> issued by   |  |
 |  |                          |  1) get   | Platform    |  |
 |  +--------------------------+           +-------------+  |
 +----------------------------------------------------------+
~~~
{: #fig-overview title="OAuth2 Assertion Flow in generic Workload Environment"}

The figure outlines the following steps which are applicable in any pattern.

* 1) retrieve credential issued by platform. The way this is acchieved and whether this is workload or platform initiated differs based on the platform.

* 2) present credential as an assertion towards an authorization server in an external authorization domain. This step uses the assertion_grant flow defined in {{RFC7521}} and, in case of JWT format, {{RFC7523}}.

* 3) On success, an access token is returned to the workload to access the protected resource.

* 4) The aaccess token is used to access the protected resource in the external authorization domain.

Accessing different protected resources may require steps 2) to 4) again with different scope parameters. Accessing a protected resource in an entirely different authorization domain often requires the entire flow to be followed again, to retrieve a new platform-issued credential with an audience for the other authorization server. This, however, differs based on the platform and implementation.

## Credential format

For the scope of this document we focus on JSON Web Token credential formats. Other formats such as X.509 certificates are possible but not as widely seen as JSON Web Tokens.

The claims in the present assertion vary greatly based on use case and actual platform, but a minimum set of claims are seen across all of them. {{RFC7523}} describes them in detail and according to it, all MUST be present.

~~~json
{
  "iss": "https://example.org",
  "sub": "my-workload",
  "aud": "custom-audience",
  "exp": 1729248124
}
~~~

For the scope of this specification, the claims can be described the following. Everything from {{RFC7523}} applies.

{:vspace}
iss
: The issuer of the workload platform. While this can have any format, it is important to highlight that many authorization servers leverage OpenID Connect {{OIDC}} and/or OAuth 2.0 Authorization Server Metadata {{RFC8414}} to retrieve JSON Web Keys {{RFC7517}} for validation purposes.

sub
: Subject which identifies the workload within the domain/workload platform instance.

audience
: One or many audiences the platform issued credential is eligable for. This is crucial when presenting the credential as an assertion towards the external authorization server which MUST identify itself as an audience present in the assertion.

# Patterns {#patterns}

## Kubernetes {#kubernetes}

In Kubernetes, the primary concept of machine identity is implemented through "service accounts" {{KubernetesServiceAccount}}. These accounts can be explicitly created or a default one is automatically assigned. Service accounts utilize JSON Web Tokens (JWTs) {{RFC7519}} as their credential format, with these tokens being cryptographically signed by the Kubernetes Control Plane.

Service accounts serve multiple authentication purposes within the Kubernetes ecosystem. They are used to authenticate to Kubernetes APIs, between different workloads and to access external resources (which is particularly relevant to the scope of this document).

To programatically use service accounts, workloads can:

* use the Token Request API {{TokenReviewV1}} of the control plane

* have the token projected into the file system of the workload. This is commonly referred to as "projected service accout token".

Both options allow workloads to:

* specify a custom audience. Possible audiences can be restricted based on policy.

* specify a custom lifetime. Maximum lifetime can be restricted by policy.

* bind the token lifetime to an object lifecycle. This allows the token to be invalidated when the object is deleted. For example, when a Kubernetes Deployment is removed from the server. It is important to highlight, that invalidation is only in effect if the Token Review API {{TokenReviewV1}} of Kubernetes is used to validate the token.

To validate service account tokens, Kubernetes offers workloads to:

* make us of the Token Review API {{TokenReviewV1}}. This API introspects the token, makes sure it hasn't been invalidated and returns the claims.

* mount the public keys used to sign the tokens into the file system of the workload. This allows workloads to decentrally validate the tokens signature.

* Optionally, a JSON Web Key Set {{RFC7517}} is exposed via a webserver. This allows the Service Account Token to be validated outside of the cluster and without line of sight towards the actual Kubernetes Control Plane API.

~~~aasvg
+-------------------------------------------------------+
|                         External Authorization Domain |
|                                                       |
| +--------------------------+ +--------------------+   |
| |                          | |                    |   |
| |   Authorization Server   | | Protected Resource |   |
| |                          | |                    |   |
| +------^-------------+-----+ +----------^---------+   |
|        |             |                  |             |
+--------+-------------+------------------+-------------+
         |             |                  |
3) present assertion   |              5) access
         |             |                  |
         |       4) access token          |
         |             |                  |
+--------+-------------+------------------+-------------+
|        |             |     +------------+  Kubernetes |
|        |             |     |                  Cluster |
|    +---+-------------v-----+----+                     |
|    |                            |                     |
|    |    Workload                |                     |
|    |                            |                     |
|    +----^----------------^------+                     |
|         |                |                            |
|         |                |                            |
|    1) schedule     2) project service                 |
|         |             account token                   |
|         |                |                            |
|   +-----+----------------+-------------------+        |
|   |                                          |        |
|   |        Kubernetes Control Plane          |        |
|   |                                          |        |
|   +------------------------------------------+        |
|                                                       |
+-------------------------------------------------------+
~~~
{: #fig-kubernetes title="OAuth2 Assertion Flow in a Kubernetes Workload Environment"}

The steps shown in {{fig-kubernetes}} are:

* 1) The Kubernetes Control Plane schedules the workload. This is much simplified and technically happens asynchronously.

* 2) The Kubernetes Control Plane projects the service account token into the workload. This step is also much simplified and technically happens alongside the scheduling with step 1.

* 3) Workloads present the project service account token as a client assertion towards an external authorization server according to {{RFC7523}}.

* 4) On success, an access token is returned to the workload to access the protected resource.

* 5) The access token is used to access the protected resource in the external authorization domain.

As an example, the following JSON showcases the claims a Kubernetes Service Account token carries.

~~~json
{
  "aud": [  # matches the requested audiences, or the API server's default audiences when none are explicitly requested
    "https://kubernetes.default.svc"
  ],
  "exp": 1731613413,
  "iat": 1700077413,
  "iss": "https://kubernetes.default.svc",  # matches the first value passed to the --service-account-issuer flag
  "jti": "ea28ed49-2e11-4280-9ec5-bc3d1d84661a",  # ServiceAccountTokenJTI feature must be enabled for the claim to be present
  "kubernetes.io": {
    "namespace": "my-namespace",
    "node": {  # ServiceAccountTokenPodNodeInfo feature must be enabled for the API server to add this node reference claim
      "name": "127.0.0.1",
      "uid": "58456cb0-dd00-45ed-b797-5578fdceaced"
    },
    "pod": {
      "name": "my-workload-69cbfb9798-jv9gn",
      "uid": "778a530c-b3f4-47c0-9cd5-ab018fb64f33"
    },
    "serviceaccount": {
      "name": "my-workload",
      "uid": "a087d5a0-e1dd-43ec-93ac-f13d89cd13af"
    },
    "warnafter": 1700081020
  },
  "nbf": 1700077413,
  "sub": "system:serviceaccount:my-namespace:my-workload"
}
~~~
{: #fig-kubernetes-token title="Example Kubernetes Service Account Token claims"}

## Secure Production Identity Framework For Everyone (SPIFFE) {#spiffe}

Secure Production Identity Framework For Everyone, also known as SPIFFE, is a cloud native compute foundation (CNCF) adopted project which defines an API definitioned called "Workload API" to delivery machine identity to workloads. Workloads can retrieve either X509 based or JWT credentials without the need to authenticate making it very easy to use. How workloads authenticate on the API is not part of the specification. It is common to use platform metadata from the operating system and the workload platform for authentication on the Workload API.

For the scope of this document, the JWT formatted credential is the most relevant one. SPIFFE referres to it as "JWT-SVID" (JWT - Single Verifyable Identity Document).

Workloads are required to specify at least one audience when requesting a JWT-SVID from the Workload API.

To allow validation, SPIFFE offers

* to download a set JWK encoded public keys that can be used to validate JWT signatures. In SPIFFE this is referred to as the "JWT trust bundle".

* invoke a validation method on the Workload API to validate JWT-SVIDs

Additionally, many SPIFFE deployments choose to separately publish the signing keys as a JSON Web Key Set on a web server to allow validation where the Workload API is not available.

The following figure illustrates how a workload can use its JWT-SVID to access a protected resource outside of SPIFFE.

~~~aasvg
+---------------------------------------------------------+
|                           External Authorization Domain |
|   +-----------------------+   +----------------------+  |
|   |                       |   |                      |  |
|   | Authorization Server  |   |  Protected Resource  |  |
|   |                       |   |                      |  |
|   +-----^-----------------+   +--------^-------------+  |
+---------+------------+-----------------+----------------+
          |            |                 |
 2) present assertion  |             4) access
          |            |                 |
          |       3) access token        |
          |            |                 |
+---------+------------+-----------------+----------------+
|  +------+------------v-----------------+----+  Workload |
|  |                                          |  Platform |
|  |                  Workload                |           |
|  |                                          |           |
|  +---------------------+--------------------+           |
|                        |                                |
|                 1) get JWT-SVID                         |
|                        |                                |
|  +---------------------v--------------------+           |
|  |                                          |           |
|  |           SPIFFE Workload API            |           |
|  |                                          |           |
|  +------------------------------------------+           |
+---------------------------------------------------------+
~~~
{: #fig-spiffe title="OAuth2 Assertion Flow in a SPIFFE Environment"}

The steps shown in {{fig-spiffe}} are:

* 1) The workload request a JWT-SVID from the SPIFFE Workload API with an audience that identifies the external authorization server.

* 2) The workload presents the JWT-SVID as a client assertion in the assertion flow based on {{RFC7523}}.

* 3) On success, an access token is returned to the workload to access the protected resource.

* 4) The access token is used to access the protected resource in the external authorization domain.

The claims of a JWT-SVID for example looks like this.
~~~json
{
  "aud": [
    "external-authorization-server"
  ],
  "exp": 1729087175,
  "iat": 1729086875,
  "sub": "spiffe://example.org/myservice"
}
~~~

TODO: write about "iss" in JWT-SVID.

## Cloud Providers {#cloudproviders}

Workload in cloud platforms can have any shape or form. Historically, virtual machines were the most common, with the introduction of containerization, hosted container environment or Kubernetes clusters were introduced, and lately, `serverless` functions are offered. Regardless of the actual workload packaging, distribution and runtime platform, all are in need of identity.

To create a common identity interface across cloud services and offerings, the pattern of an `Instance Metadata Endpoint` has been established by the biggest cloud providers. Next to the option for workloads to get metadata about themselves, it also allows them to receive identity. The credential types offered can vary. JWT, however, is the one that is common across all of them. The issued credential allows proof to anyone it is being presented to, that the workload platform has attested the workload and it can be considered authenticated.

Within a cloud provider the issued credential can often directly be used to access resources of any kind across the platform making integration between the services easy and `credential less`. While the term is technically missleading, from a user perspective, no credential needs to be issued, provisioned, rotated or revoked, as everything is handled internally by the platform.

Resources outside of the platform, for example resources or workloads in other clouds, generic web servers or on-premise resources, are most of the time, however, protected by different domains and authorization servers and deny the platform issued credential. In this scenario, the pattern of using the platform issued credential as an assertion in the context of {{RFC7521}}, for JWT particularly {{RFC7523}} towards the authorization server that protected the resource to get an access token.

~~~aasvg
   +-----------------------------------------------------+
   |                       External Authorization Domain |
   |                                                     |
   | +------------------------+  +---------------------+ |
   | |                        |  |                     | |
   | | Authorization Server   |  | Protected Resource  | |
   | |                        |  |                     | |
   | +------^------------+----+  +----------^----------+ |
   |        |            |                  |            |
   +--------+------------+------------------+------------+
            |            |                  |
B1) present as assertion |              B3) access
            |            |                  |
            |       B2) access token        |
            |            |   +--------------+
   +--------+------------+---+------------------------------+
   |        |            |   |                        Cloud |
   |        |            |   |                              |
   |   +----+------------v---+--+ 1) get       +----------+ |
   |   |                        |    identity  |          | |
   |   |        Workload        +--------------> Instance | |
   |   |                        |              |          | |
   |   +-----------+------------+              | Metadata | |
   |               |                           |          | |
   |           A1) access                      | Service/ | |
   |               |                           | Endpoint | |
   |   +-----------v------------+              |          | |
   |   |                        |              +----------+ |
   |   |   Protected Resource   |                           |
   |   |                        |                           |
   |   +------------------------+                           |
   +--------------------------------------------------------+
~~~
{: #fig-cloud title="OAuth2 Assertion Flow in a cloud environment"}

The steps shown in {{fig-cloud}} are:

* 1) The workload retrieves identity from the Instance Metadata Endpoint.

In case the workload needs to access a resource within the cloud (protected by the same authorization server that issued the workload identity)

* A1) The workload directly access the protected resource with the credential issued in step 1.

In case the workload needs to access a resource outside of the cloud (protected by a different authorization server). This can also be the same cloud but different context (tenant, account).

* B1) The workload presents cloud-issued credential as an assertion towards the external authorization server using {{RFC7523}}.

* B2) On success, an access token is returned to the workload to access the protected resource.

* B3) Using the access token, the workload is able to access the protected resource in the external authorization domain.

## Continues integration/deployment systems {#cicd}

Continous integration and deployment systems allow their pipelines/workflows to receive identity every time they run. Particularly in situations where build outputs need to be uploaded to resources protected by other authorization server, deployments need to be made, or more generally, protected resources to be accessed, {{RFC7523}} is used to federate the pipeline/workflow identity to an identity of the other authorization server.

~~~aasvg
+----------------------------------------------------------+
|                            External Authorization Domain |
| +--------------------------+     +---------------------+ |
| |                          |     |                     | |
| |   Authorization Server   |     |  Protected Resource | |
| |                          |     |                     | |
| +-------^-------------+----+     +------------^--------+ |
|         |             |                       |          |
+---------+-------------+-----------------------+----------+
          |             |                       |
3) present assertion    |                  4) access
          |             |                       |
          |      4) access token                |
          |             |                       |
+---------+-------------v-----------------------+----------+
|                                                          |
|                    Task (Workload)                       |
|                                                          |
+--------^---------------------------+---------------------+
         |                           |
   1)schedules                2)retrieve identity
         |                           |
+--------+---------------------------v---------------------+
|                                                          |
|       Continuous Integration / Deployment Platform       |
|                                                          |
+----------------------------------------------------------+
~~~
{: #fig-cicd title="OAuth2 Assertion Flow in a continous integration/deployment environment"}

The steps shown in {{fig-cicd}} are:

* 1) The continuous integration / deployment platform (CI-CD platform) schedules a task (considered a workload) to be performed.

* 2) The workload is able to retrieve identity from the CI-CD platform. This can differ based on the platform and potentially is already supplied during scheduling phase in step 1.

* 3) The workload presents the CI-CD issued credential as an assertion towards the authorization server in the external authorization domain based on {{RFC7521}}. In case of JWT also {{RFC7523}}.

* 4) On success, an access token is returned to the workload to access the protected resource.

* 5) Using the access token, the workload is able to access the protected resource in the external authorization domain.

Tokens of different providers look different, but all of them contain claims carrying the basic context of the executed tasks such as source code management data (e.g. git branch), initiation and more.

# Security Considerations

This entire document is about security.

# IANA Considerations {#IANA}

This document does not require actions by IANA.

# Acknowledgements

Add your name here.

--- back
