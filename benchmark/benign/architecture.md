# Architecture

The service has three layers: an HTTP handler, a domain layer, and a storage adapter. Requests are validated at the edge and passed as typed commands to the domain layer, which is the only place business rules live.
