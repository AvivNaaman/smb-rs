# Parallelization
One of the most challenging aspects of working with SMB is achieving efficient parallelization. This page review common facts and examples, showing how to properly parallelize SMB operations in your applications.

## Background: The SMB protocol
The SMB protocol supports (in most of the newer SMB2 dialects), the "large MTU" feature. This feature basically allows sending multiple requests to the server at once, without having to wait for each individual response between reequests. This is implemented by a credit system -- the client asks the server to grant N credits, and each message consumes some of those credits - depending on the message size and type.
This great feature is also supported in this crate: If you are building the crate with the "async" or the "multi_threaded" features, you can share your SMB resources between threads to allow concurrent access and proper initialization of the available network bandwidth, by sending requests and processing informations even when awaiting for responses to get back.
The credits system is implemented per-connection -- and therefore, you should only have ONE connection between your client and a certain server. In case you have multiple network adapters, that possibly allow improving your bandwidth by connecting to multiple endpoints (i.,e. esatbilishing multiple connections bwteen the same client and server, on different network adapters) - SMB has a solution for that too, which is called multi-channel.

## Practice: How should I do it?
In practice, using this crate should be straightforward when you need to parallelize operations: You need to open your resource, and simply spawn some tasks (or threads) that share a reference to that resource. In turn, you may definitely perform operations on the resource from multiple tasks or threads at the same time, and thread safety is guaranteed by the crate!
1. Open your common resource.
2. Divide your work into tasks that can be performed concurrently.
3. Spawn the tasks, sharing the resource reference.
4. Avoid locks on long-running tasks.

## Examples
### Parallel file copy
Refer to the [`crate::resource::file_util::block_copy`] function: it implements a parallel file copy operation, both in async and multi-threaded modes. The function starts a number of workers, shares the open remote file, and each task acquires a lock, chooses the next data block to read or write from the remote file, and performs the operation concurrently.
In practice, taking a look at a sniffing of a copy session that uses parallel copy, you may notice many requests getting sent over the wire before responses arrive, and even responses that arrive in a non-deterministic, out-of-sequence manner. This shows that operations are indeed being processed in parallel, making efficient use of the available bandwidth.
- In this example, as mentioned, the `File` instance is being shared between the tasks, using `Arc<File>` to allow concurrent access (`File` provides many a rich api that accepts a safe `&self` argument).
- No locking is performed at all - the only synchronization mechanism used when copying the file is an `AtomicU64`, describing the current position in the file being copied.

## Additional resources & references
* The SMB protocol documentation - MS-SMB2
  * Multi-Credit documentation resources [Credit Charge](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/18183100-026a-46e1-87a4-46013d534b9c), [Granting Message Credits](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/dc517c41-646d-4d0b-b7b3-25a53932181d), [Verifying the Sequence Number](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/0326f784-0baf-45fd-9687-626859ef5a9b)
  * Multi-Channel example: [Establish Alternate Channel](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/2e32e57a-166f-46ae-abe8-17fa3c897890)
* [Samba Wiki/SMB2 Credits](https://wiki.samba.org/index.php/SMB2_Credits)
* SNIA.org - Smb3 in samba - [Multi-Channel and beyond](https://www.snia.org/sites/default/files/SDC/2016/presentations/smb/Michael_Adam_SMB3_in_Samba_Multi-Channel_and_Beyond.pdf)
* Issue [#104](https://github.com/AvivNaaman/smb-rs/issues/104) - "Parallelize File fetching and downloading"