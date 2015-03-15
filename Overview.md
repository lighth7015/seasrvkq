The main document describing the whole system is available only in Russian, it is [Sender and It's History](http://seasrvkq.googlecode.com/svn/wiki/senderhist.html)
See also SEAProtocol for graphical protocol illustration.

### Admin or programmer? ###

Download, unpack, compile, install. All as usual, except that you can use `.shar`-archive which will download and compile it for you.

But you don't really want to **use** this - take a something more modern. This is of primary interest for programmers - how to write a relatively elegant solution for a legacy shit (but still actively used shit!).

# In abstract #

This is a network server daemon for simple LAN instant messaging protocol, handling many concurrent connections. It is written using implicit FSM, not thread-per-client, see http://www.kegel.com/c10k.html for details about this type of servers.

It is non-portable and written for FreeBSD, because protocol is ugly and useful only at it's place of birth - and here it is more easy to write using features than to be portable. You may try to build it on other OSes with libkqueue, though.

This is only a short description, the whole topic is not for the faint-hearted, you must know many things: dealing with signals, sockets, overall Unix programming, etc. But you may be not familiar with FreeBSD `kqueue()` - than this source is for you, for education purposes.

# Low level #

So it uses non-blocking sockets, see W. R. Stevens books "UNIX Network Programming" for more on this hard topic.

Then have a look to [BSD macros for linked lists](http://www.freebsd.org/cgi/man.cgi?query=queue).

## Dbufs ##

This is a group messenger, so there is data which is copied unchanged to many recipients. It is handled with `dbuf` structure, a data buffer with a reference counter.

There are `make_dbuf()`, `alloc_dbuf()`, `attach_dbuf()` and `free_dbuf()` for manipulating them.

## Output queues and writing ##

Each socket has it's own output queue. You can add a data to this queue via `append_outbufq()`, which copies your simple data and increments reference counter if you pass a `dbuf`. This is because headers often vary for each destination, but then follows the same data (e.g. message text body) for all of them. Internally, `append_outbufq()` makes some clever tricks to optimize memory using - so you may not care about ineffectiveness of adding single bytes to buffers.

That is only adding. To actually send data, call `try_write()`, which also is a demonstration of different techniques from W. R. Stevens books. It writes as many as possible and returns number of bytes written or connection error.

## `kqueue()` and level-triggering ##

The `kqueue()` does level-triggering - like level of water in a tank. It will always return "available to write" event while you may have already nothing to write for that client. You may have change to edge-triggering (an event of changed level, e.g. packet sent or arrived), but that has nothing to deal with our own needs to write to client at unspecified time.

So we disable reporting "available to write" events when we have nothing to write, and use `schedule_write()` to enable reporting them back when we have added something to output queue. This function doesn't try to write itself, though.

# Order of function calls #

You may have noted that function does not actually write. Why? Because we are single-threaded FSM. There may be too many dependencies between functions.

Imagine `func1()` processes several users and calls `func2()` for one of them which calls `kill_user()` for another of them. Then on return `func1()` will go to next user in list which is already killed and `free()`'d. Oops.

So you should be always careful and process each event separately from top-level infinite loop. `kqueue()` cares for you about closed descriptors and combines other events (e.g. seven 1000-byte packets arrived to `read()`, there will be one summary event for 7000 bytes to read, not 7 events). Deferring function calls may be also useful for other natural optimizations due to combined operations (e.g. you do several appends to client, calling `try_write()` once later will be more effective then each time).

# Signals, loop and controlling #

Top-level event loop runs in `main()`, and `event_loop()` processes one event. It calls `handle_*()` family of functions, and also `accept_client()` and `login_timeout()` and `admin_command()`.

Top-level loop also calls `process_timer()` and `admin_command()` for one of signals (only to demonstrate both types of signal handling).

In Unix the only safe operation for a signal is to set a variable. So later it is checked in the top-level event loop. This program however is a demonstration of both traditional signal processing and `kqueue()` signal facilities.

Controlling daemon via `readlink()` is somewhat weird, but simple for small number of commands, though.

# Timers #

`kqueue()` has a limit for number of timers, so we use not many of them. Login timers were simply much more easier to do with separate timers than to roll out yet another timing queue. Consider the second approach if your application will handle much more clients than this protocol's limit :-)

# Other #

There are some tries to have functions for generic cases, like `parse_*()` and `connect_sock()`. It is currently not of much use, but demonstrates how to do non-blocking `connect()` in generic case on FreeBSD (Stevens tells this is usually OS-dependent). In the future there may be for gateway to another not-so-ugly protocol, not only for archiver...

# That's all for tonight! #

So, read comments and think, there is too many of them...