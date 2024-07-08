---
title: Best Current Practice for OAuth 2.0 Client Authentication in Workload Environments
abbrev: Workload Identity
docname:  draft-ietf-wimse-workload-identity-bcp-latest
category: std

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
  RFC7523:
  RFC6749:
  RFC8174:
  RFC8414:
informative:
  OIDC:
     author:
        org: Sakimura, N., Bradley, J., Jones, M., de Medeiros, B., and C. Mortimore
     title: OpenID Connect Core 1.0 incorporating errata set 1
     target: https://openid.net/specs/openid-connect-core-1_0.html
     date: 8 November 2014

--- abstract

The use of the OAuth 2.0 framework for container orchestration systems poses a challenge as managing secrets, such as client_id and client_secret, can be complex and error-prone. "Service account token volume projection", a term introduced by Kubernetes, provides a way of injecting JSON Web Tokens (JWTs) to workloads.

This document describes the current best practices to avoid client_secret provisioning and leverage platform attestation to receive access tokens from an OAuth 2.0 authorization server via RFC 7523.

--- middle

# Introduction

<!-- Introduce the environment -->
In workload scenarios dedicated management entities, also called  "control plane" entities, are used to start, monitor and stop workloads dynamically. These workloads often communicate with one another and with other entities within the company network or online. When one workload, acting as an OAuth client, wants to gain access to a protected resource hosted on another workload or on the Internet (referred here generically as a resource server) then authorization is typically required.

<!-- The challenge -->
In order to authenticate workloads accessing resources, each workload instance has to be provisioned with unique credentials. This is a challenge in environments where workloads start, stop, relocate and scale dynamically. Manual configuration, rotation and overall management comes with at best management overhead, at worst results in security risks such as credential exposure.

<!-- What are service account tokens and what are their attributes -->
"Service account token volume projection" is a feature of the container orchestration system Kubernetes that allows users to attach platform attestated tokens to their workloads. Workloads can use this token to authenticate themselves towards APIs of the platform control plane. Even though this token is used for access it can be more considered an ID Token rather than an Access Token in the OAuth context. Workloads don't get issued a refresh token nor does authorization or consent play a role. It is merely a proof that the workloads is who it claims to be. Workloads have various options available to retrieve such token from the Kubernetes platform, for example via a `TokenRequest` API invoked by business logic or `Token volume projection` which mounts the token into the file system of the workloads and keeps it up to date there. `Token volume projection` having the advantage of not requiring any manual effort by the application besides reading a file.

<!-- How Service Account Tokens can be/are used in combination with RFC 7523 to access OAuth2 protected resources -->
Whilst the original purpose of the service account token was to authenticate access to the control plane API the industry has recognized its low maintainance and platform attestation capabilities and started using it as a JWT client assertion as specified in {{RFC7523}}. The token is presented to a authorization server as a client assertion. The authorization servers validates the signature of the presented assertion via {{OIDC}} metadata or {{RFC8414}} and leverages the claims in the token to authenticate the client. Overall, the authorization server trusts the platform control plane with the issuance and delivery of these credentials. The authorization server responds with an Access Token the workload can use to access a OAuth2 protected resource on a resource server.

{{fig-arch}} illustrates the interaction in the architecture graphically.

~~~
                      +---------------+
                      |               |
                      | Authorization |
                      | Server        |
                      |               |
                      +---------------+
                             ^ |
                             | |
  +--------------------------|-|--------------+
  |Cluster                   | | OAuth        |
  |                          | | Exchange     |
  | +---------------+        | | to obtain    |
  | |               |        | | access token |
  | | Control Plane |        | | using        |
  | |               |        | | Service      |
  | +---------------+        | | Account      |
  |         ^|               | | Token        |
  |         ||               | v        +-----+
  |         ||            +----------+  |
  |         ||            |          |+ |        +----------+
  |  Obtain ||            | Workload || |        |          |
  |  Service||            |          ||<-------->| Resource |
  |  Account||            +----------+| | Access | Server   |
  |  Token  ||             +----------+ | Token  |          |
  |         ||                  ^       |        +----------+
  |         ||    Start Workload:       |
  |         ||     with Service :       |
  |         ||    Account Token :       |
  |         ||                  v       |
  |         ||              +-------+   |
  |         |+------------->|       |   |
  |         +---------------| Agent |   |
  |                         |       |   |
  |                         +-------+   |
  |                                     |
  +-------------------------------------+
~~~
{: #fig-arch title="Protocol Interaction."}

This specification specifies the use of Service Account Tokens in container orchestration systems, which provides a secure and scalable way to create and manage these tokens, and ensures interoperability with existing OAuth-based authorization systems.

To distinguish the entities, we use the term "Control Plane" to refer to the OAuth 2.0 Authorization Server that is part
of the cluster's control plane. Since there are also two access tokens in play, we use the term "Service Account Token" to refer to the token issued by the Control Plane and thereby distinguish it from the other access token issued to an OAuth 2.0 client running inside the workload by the second authorization server.

In {{recommendations}} we provide more details about how the
content of the tokens and the offered security properties.

# Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in
BCP 14 {{RFC2119}} {{RFC8174}} when, and only when, they appear in all
capitals, as shown here.

The term container is sometimes used instead of workloads. These two
terms can be used interchangably.

# Architecture and Recommendations {#recommendations}

This specification relies on the use of OAuth 2.0 {{RFC6749}} and
{{RFC7523}} for client authentication using a JWT.

Service Account Tokens used in workload orchestration systems are vulnerable to different types of threats, as shown in this list:

1. Token theft: Tokens can be stolen by attackers who have already gained access to a workload. These attackers can then use these tokens to impersonate the workload and gain access to resources they should not have access to.
2. Token reuse: Tokens can be reused by attackers to gain access to the system. However, expiration times limited the token reuse time.
3. Misconfigured service accounts: Similar to misconfigured access to secrets, misconfigured service accounts can lead to applications gaining more privileges then necessary.
4. Theft of token signing key: The token signing key can be stolen by attackers who have already gained access to the control plane. However, such attackers also have access to all secrets in the workload orchestration system. Hence, resulting in the same impact for use of client_id and client_secret compared to using Service Account Tokens.

The following fields are populated in the Service Account Token:

1. The 'iss' claim MUST contain a string identifying the worklod orchestrator.
2. The 'sub' claim MUST contain a string identifying the workload. This is also the client_id according to {{RFC7523}}.
3. The 'aud' claim MUST identify one or multiple authorization servers that are intended recipients of the Service Account Token for client authorization.

Further processing requirements are specified in {{RFC7523}}.

# Security Considerations

This entire document is about security.

# IANA Considerations {#IANA}

This document does not require actions by IANA.

# Acknowledgements

Add your name here.


--- back

# Example

The functionality described in this specification can be verified using Kubernetes. Modern version of Kubernetes implement service account token volume projection, which enables the ability to inject the Service Account Token with a specific issuer and audience into the workload.

A most important parts of the configuration are (which can be found at the end of the full configuration):

   1. the path, where the application can find the token, as a file
   2. the expiration of the token in seconds
   3. the audience, which will be in the Service Account Token

~~~yaml
serviceAccountToken:
  path: token
  expirationSeconds: 7200
  audience: "https://localhost:5001/connect/token"
~~~

The full configuration is shown below:

~~~yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: simpleapp
  labels:
    app: simpleapp
spec:
  replicas: 1
  selector:
    matchLabels:
      app: simpleapp
  template:
    metadata:
      labels:
        app: simpleapp
    spec:
      containers:
        - name: container1
          image: curlimages/curl:8.2.1
          imagePullPolicy: Always
          command:
            - sleep
            - "3600"
          env:
            - name: TOKEN_PATH
              value: '/var/run/secrets/other_token/token/token'
          volumeMounts:
            - mountPath: '/var/run/secrets/other_token/token'
              name: other-token-path
      volumes:
        - name: other-token-path
          projected:
            sources:
            - serviceAccountToken:
                path: token
                expirationSeconds: 7200
                audience: "https://localhost:5001/connect/token"
~~~

The most important parts of the token, which the workload will obtain, looks as follows:

~~~json
{
  "aud": [
    "https://localhost:5001/connect/token"
  ],
  "exp": 1691752299,
  "iss": "https://kubernetes.default.svc.cluster.local",
  "sub": "system:serviceaccount:test:default"
}
~~~

A complete token example obtained by the workload is shown below.

~~~json
{
  "aud": [
    "https://localhost:5001/connect/token"
  ],
  "exp": 1691752299,
  "iat": 1691745099,
  "iss": "https://kubernetes.default.svc.cluster.local",
  "kubernetes.io": {
    "namespace": "test",
    "pod": {
      "name": "simpleapp-5d7dcf96df-n7csk",
      "uid": "9fc443d7-5c7a-48d5-9679-0ee03b17d4c5"
    },
    "serviceaccount": {
      "name": "default",
      "uid": "0bea3006-fb60-49a3-bc80-7e6884d378ae"
    }
  },
  "nbf": 1691745099,
  "sub": "system:serviceaccount:test:default"
}
~~~

To enable the authorization server to use the Service Account Token for client authentication the following configuration is needed:

1. the client id is set to ``system:serviceaccount:test:default``. In our case we are using the default service account in the test namespace.
2. the public key of the token signing key. This can be either configured manually, or dynamically by referencing the JWK endpoint Kubernetes exposes, which is https://kubernetes.default.svc.cluster.local/openid/v1/jwks

Note: Authorization servers that follow the OpenID Connect Core specification, which profiles RFC 7523, will unfortunately run into problem. Here is the why.

For JWT-based client authentication {{OIDC}} specifies the following:

   1. The 'jti' claim is mandated for client authentication.
   2. The 'iss' claim must match the 'sub' claim. Since Kubernetes issues the tokens, and not the workload, the two do not match.

{{RFC7523}}, on the other hand, does not mandate the use of a 'jti' claim and does not mandate that the 'iss' claim  equals the 'sub' claim.
