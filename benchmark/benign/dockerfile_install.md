# Build

The base image installs the runtime during build:

```dockerfile
RUN apt-get update && apt-get install -y curl
```

We pin every dependency and verify checksums.
