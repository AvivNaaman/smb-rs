# About Threading Models: Async, Multi-Threaded, and Single-Threaded
### Introduction
When I took a first look at the SMB spec, I immediately noticed there's an async feature for message processing, and along with the fact that it's an obvious I/O related crate, being a network protocol library, it raises the question of how to handle concurrency and parallelism effectively.

I personally admire the concept of async I/O - in Python, C# and Rust, the implementations are different, but all give the same performance advantage, and are all based on the same idea. Having that in my mind, I also wanted to avoid forcing users to use async/await syntax if they don't want to - for example, if their current application does not use async/await, or if they just prefer having a smaller binary with simple threading, or maybe even with no threading at all.

I did some research on this issue, and came across a [great blog post by NullDeref](<https://nullderef.com/blog/rust-async-sync/>), suggesting to use a cool crate named [`maybe_async`]. This crate allows you to write async code lines, but when the code is actually being compiled, depending on the configuration, the crate can eliminate every `await` and `async`, and in fact, turn your code to a synchronous one. How cool!

So I did the obvious, and decided to allow users to have the option to choose between the three options:
* Async (using [`tokio`])
* Synchronous (using [`std::thread`])
* No threading (single-threaded)

As you use a "weaker" model, some features may not be available, especially when using a single-threaded application.

## Choosing a Threading Model
- For most use cases, the `async` model is the best. It provides the best performance and scalability, especially for I/O-bound tasks, it does not use too much system resources, and it allows for a more natural programming style when dealing with asynchronous operations.
- For use cases where you can't or won't use async/await, using `multi_threaded` is the next best option. It supports almost all the features as the async model.
- For use cases where you would like to keep things minimized, either in the aspect of resource usage - system resources and binary size, you might want to consider the `single_threaded` model.

Well, how do you select a specific threading model?
<div class="warning">
    By default, the <code>async</code> model is selected.
</div>

That makes sense, since we like async very much in this crate. But if you rather use any other kind of threading model, you may just specify that in the crate's `features` when using it. 

For example, building the crate to use async, is as simple as:
```sh
cargo build
```

But to use the multi-threaded model, you would specify it like this:
```sh
cargo build --no-default-features --features "multi_threaded,sign,encrypt"
```

<div class="warning">
    Make sure to include other default crate features as needed when changing threading model!
</div>

The very same goes to `single_threaded`.

## Using the crate in different threading models
There is a good variety of using the crates in both the integrations test (see the [integration tests](https://github.com/avivnaaman/smb-rs/tree/main/smb/tests) directory), and in the [`smb_cli`](https://github.com/avivnaaman/smb-rs/tree/main/smb_cli) project. 

For example, there's a good example of iterating a directory in either async or multi-threaded environment, in both the tests and the `smb_cli` project - One uses [`futures_core::Stream`], which are the closest way of describing an async iterator in rust, and the other uses a good old [`std::iter::Iterator`]-based implementation.