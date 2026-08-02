pub(super) const HTTP_FIXTURE: &str = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: oxibelt
spec:
  controllerName: oxibelt.dev/gateway-controller
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: edge
  namespace: default
spec:
  gatewayClassName: oxibelt
  listeners:
  - name: https
    protocol: HTTPS
    port: 443
    hostname: api.example.com
---
apiVersion: v1
kind: Service
metadata:
  name: app
  namespace: default
spec:
  ports:
  - name: http
    port: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: canary
  namespace: default
spec:
  ports:
  - name: http
    port: 8080
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: app
  namespace: default
spec:
  parentRefs:
  - name: edge
    sectionName: https
  hostnames:
  - api.example.com
  rules:
  - matches:
    - path:
        type: PathPrefix
        value: /api
      method: GET
    backendRefs:
    - name: app
      port: 8080
      weight: 80
    - name: canary
      port: 8080
      weight: 20
"#;

pub(super) const CROSS_NAMESPACE_WITHOUT_GRANT: &str = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: oxibelt
spec:
  controllerName: oxibelt.dev/gateway-controller
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: edge
  namespace: frontend
spec:
  gatewayClassName: oxibelt
  listeners:
  - name: http
    protocol: HTTP
    port: 80
---
apiVersion: v1
kind: Service
metadata:
  name: app
  namespace: backend
spec:
  ports:
  - port: 8080
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: app
  namespace: frontend
spec:
  parentRefs:
  - name: edge
  rules:
  - backendRefs:
    - name: app
      namespace: backend
      port: 8080
"#;

pub(super) const CROSS_NAMESPACE_WITH_GRANT: &str = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: oxibelt
spec:
  controllerName: oxibelt.dev/gateway-controller
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: edge
  namespace: frontend
spec:
  gatewayClassName: oxibelt
  listeners:
  - name: http
    protocol: HTTP
    port: 80
---
apiVersion: gateway.networking.k8s.io/v1beta1
kind: ReferenceGrant
metadata:
  name: allow-frontend
  namespace: backend
spec:
  from:
  - group: gateway.networking.k8s.io
    kind: HTTPRoute
    namespace: frontend
  to:
  - group: ""
    kind: Service
---
apiVersion: v1
kind: Service
metadata:
  name: app
  namespace: backend
spec:
  ports:
  - port: 8080
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: app
  namespace: frontend
spec:
  parentRefs:
  - name: edge
  rules:
  - backendRefs:
    - name: app
      namespace: backend
      port: 8080
"#;

pub(super) const UNSUPPORTED_HEADER_REGEX: &str = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: oxibelt
spec:
  controllerName: oxibelt.dev/gateway-controller
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: edge
  namespace: default
spec:
  gatewayClassName: oxibelt
  listeners:
  - name: http
    protocol: HTTP
    port: 80
---
apiVersion: v1
kind: Service
metadata:
  name: app
  namespace: default
spec:
  ports:
  - port: 8080
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: app
  namespace: default
spec:
  parentRefs:
  - name: edge
  rules:
  - matches:
    - headers:
      - name: x-env
        type: RegularExpression
        value: prod|stage
    backendRefs:
    - name: app
      port: 8080
"#;

pub(super) const TLS_FIXTURE: &str = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: oxibelt
spec:
  controllerName: oxibelt.dev/gateway-controller
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: edge
  namespace: default
spec:
  gatewayClassName: oxibelt
  listeners:
  - name: tls
    protocol: TLS
    port: 443
    hostname: db.example.com
    tls:
      mode: Passthrough
---
apiVersion: v1
kind: Service
metadata:
  name: db
  namespace: default
spec:
  ports:
  - port: 5432
---
apiVersion: gateway.networking.k8s.io/v1
kind: TLSRoute
metadata:
  name: db
  namespace: default
spec:
  parentRefs:
  - name: edge
    sectionName: tls
  hostnames:
  - db.example.com
  rules:
  - backendRefs:
    - name: db
      port: 5432
"#;

pub(super) const HTTP_FILTER_FIXTURE: &str = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: oxibelt
spec:
  controllerName: oxibelt.dev/gateway-controller
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: edge
  namespace: default
spec:
  gatewayClassName: oxibelt
  listeners:
  - name: http
    protocol: HTTP
    port: 80
---
apiVersion: v1
kind: Service
metadata:
  name: app
  namespace: default
spec:
  ports:
  - port: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: mirror
  namespace: default
spec:
  ports:
  - port: 8081
---
apiVersion: v1
kind: Service
metadata:
  name: auth
  namespace: default
spec:
  ports:
  - port: 9000
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: app
  namespace: default
spec:
  parentRefs:
  - name: edge
  rules:
  - matches:
    - path:
        type: PathPrefix
        value: /app
    filters:
    - type: RequestHeaderModifier
      requestHeaderModifier:
        set:
        - name: x-gateway-route
          value: app
    - type: ResponseHeaderModifier
      responseHeaderModifier:
        add:
        - name: x-served-by
          value: oxibelt
    - type: CORS
      cors:
        allowOrigins:
        - https://app.example.com
        allowMethods:
        - GET
        allowHeaders:
        - authorization
        exposeHeaders:
        - x-served-by
        allowCredentials: true
        maxAgeSeconds: 600
    - type: RequestMirror
      requestMirror:
        backendRef:
          name: mirror
          port: 8081
        percent: 25
    - type: ExternalAuth
      externalAuth:
        protocol: HTTP
        backendRef:
          name: auth
          port: 9000
        http:
          path: /verify
          allowedHeaders:
          - authorization
          allowedResponseHeaders:
          - x-auth-user
          - www-authenticate
        forwardBody:
          maxSize: 4096
    backendRefs:
    - name: app
      port: 8080
"#;

pub(super) const GRPC_FIXTURE: &str = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: oxibelt
spec:
  controllerName: oxibelt.dev/gateway-controller
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: edge
  namespace: default
spec:
  gatewayClassName: oxibelt
  listeners:
  - name: https
    protocol: HTTPS
    port: 443
    allowedRoutes:
      namespaces:
        from: All
---
apiVersion: v1
kind: Service
metadata:
  name: echo
  namespace: default
spec:
  ports:
  - port: 50051
---
apiVersion: v1
kind: Service
metadata:
  name: mirror
  namespace: default
spec:
  ports:
  - port: 50052
---
apiVersion: gateway.networking.k8s.io/v1
kind: GRPCRoute
metadata:
  name: echo
  namespace: rpc
spec:
  parentRefs:
  - name: edge
    namespace: default
  rules:
  - matches:
    - method:
        service: pkg.Echo
        method: Say
      headers:
      - name: x-tenant
        value: acme
    filters:
    - type: RequestHeaderModifier
      requestHeaderModifier:
        add:
        - name: x-grpc-route
          value: echo
    - type: RequestMirror
      requestMirror:
        backendRef:
          name: mirror
          namespace: default
          port: 50052
    backendRefs:
    - name: echo
      namespace: default
      port: 50051
---
apiVersion: gateway.networking.k8s.io/v1beta1
kind: ReferenceGrant
metadata:
  name: allow-rpc
  namespace: default
spec:
  from:
  - group: gateway.networking.k8s.io
    kind: GRPCRoute
    namespace: rpc
  to:
  - group: ""
    kind: Service
"#;

pub(super) const UNSUPPORTED_GRPC_EXTERNAL_AUTH: &str = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: oxibelt
spec:
  controllerName: oxibelt.dev/gateway-controller
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: edge
  namespace: default
spec:
  gatewayClassName: oxibelt
  listeners:
  - name: https
    protocol: HTTPS
    port: 443
---
apiVersion: v1
kind: Service
metadata:
  name: echo
  namespace: default
spec:
  ports:
  - port: 50051
---
apiVersion: v1
kind: Service
metadata:
  name: auth
  namespace: default
spec:
  ports:
  - port: 9000
---
apiVersion: gateway.networking.k8s.io/v1
kind: GRPCRoute
metadata:
  name: echo
  namespace: default
spec:
  parentRefs:
  - name: edge
  rules:
  - filters:
    - type: ExternalAuth
      externalAuth:
        protocol: GRPC
        backendRef:
          name: auth
          port: 9000
    backendRefs:
    - name: echo
      port: 50051
"#;

pub(super) const TCP_ROUTE_FIXTURE: &str = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: TCPRoute
metadata:
  name: tcp
  namespace: default
spec:
  rules:
  - backendRefs: []
"#;
