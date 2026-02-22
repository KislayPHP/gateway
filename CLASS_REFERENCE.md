# Gateway Class Reference

Runtime classes exported by `kislayphp/gateway`.

## Namespace

- Primary: `Kislay\\Gateway`
- Legacy alias: `KislayPHP\\Gateway`

## `Kislay\\Gateway\\Gateway`

API gateway/reverse proxy class for route-to-upstream and service-to-upstream routing.

### Constructor

- `__construct()`
  - Create a gateway instance.

### Static Route Mapping

- `addRoute(string $method, string $path, string $target)`
  - Map request route to fixed upstream URL.

### Service Route Mapping

- `addServiceRoute(string $method, string $path, string $service)`
  - Map request route to logical service name.
- `setResolver(callable $resolver)`
  - Resolve service name to upstream URL dynamically.
- `setFallbackService(string $service)`
  - Fallback logical service when no route matches.
- `setFallbackTarget(string $target)`
  - Fallback fixed target when no route/service resolves.

### Runtime and Lifecycle

- `setThreads(int $count)`
  - Set worker thread count (NTS-safe fallback applies).
- `routes()`
  - Return current gateway route table.
- `listen(string $host, int $port)`
  - Start gateway listener.
- `stop()`
  - Stop gateway listener.
