# Connection Core Module
First, let's define some terms:
- "multi" refers to ANY threading model that might contain more than one thread or task - it could be async or multi-threaded.
- "single" refers to a single-threaded model.
- "async" is the async/await model.
- "multi-threaded" is the traditional multi-threaded model, with `std::thread` or similar.
## Design overview
1. The most basic unit is the `Worker` trait, which defines the basic operations of a worker, such as `start`, `stop`, `send`, `receive`.
2. The `SingleWorker` is a simple implementation of `Worker` trait, which is single-threaded.
3. The `MultiWorkerBase` is a more complex implementation of `Worker` trait, which is multi-threaded.
   1. The `MultiWorkerBase` uses a `MultiWorkerBackend` trait to define the backend operations.
   2. Since much of the common logic is shared between different backends (for example, waiting for a message to be received), the `MultiWorkerBackend` trait is used to define the common operations.
   3. The `ThreadingBackend` and `AsyncBackend` are two implementations of `MultiWorkerBackend` trait, which are multi-threaded and async respectively.
4. The `ConnectionMessageHandler` is the high-level logic that uses the `Worker` trait to send and receive messages.
```mermaid
classDiagram
class ConnectionMessageHandler
    ConnectionMessageHandler : sendo()
    ConnectionMessageHandler : recvo()
    ConnectionMessageHandler *-- Worker

class Worker
    <<trait>> Worker
    Worker : start()
    Worker : stop()
    Worker : send()
    Worker : receive()
class SingleWorker
    Worker <|-- SingleWorker
class MultiWorkerBase~B: MultiWorkerBackend~
    Worker <|-- MultiWorkerBase

class MultiWorkerBackend
    <<trait>> MultiWorkerBackend
    MultiWorkerBackend : start()
    MultiWorkerBackend : stop()
    MultiWorkerBackend : do_send()
    MultiWorkerBackend : do_receive()
    MultiWorkerBackend *-- MultiWorkerBase
class ThreadingBackend
    MultiWorkerBackend <|-- ThreadingBackend
    ThreadingBackend : loop_send()
    ThreadingBackend : loop_receive()
class AsyncBackend
    MultiWorkerBackend <|-- AsyncBackend
    AsyncBackend : loop_fn()

```
This is a general overview of the design, the actual implementation is slightly different, but the basic idea is the same. Visit the module's source code for more details.
