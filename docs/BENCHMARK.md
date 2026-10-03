# Benchmark

`make bench` measures a real hushd under load. For each run, `bench/bench` starts hushd
on a fresh folder, connects N clients over TCP that log in together, then has each one
post M messages to the whole chat. Every message goes to all N clients, the sender
included, so a run delivers N × N × M messages. It reports how long the logins took,
how fast the server delivered, and how long each message took from being sent to
reaching each recipient.

Some details matter when reading the numbers:

- hushd allows 16 connections per address, so the clients connect from 127.0.0.1
  through 127.0.0.32. The server's own limit is 512 connections.
- The clients' identities are on the admin list, so nobody waits for approval.
- Message bodies are 200 random bytes with the send time at the front. The server
  can't read bodies, so it does the same work as for real messages: size checks, an
  SQLite insert, and a copy for everyone in the chat.
- "All at once" means each client queues all its messages immediately, far more than
  people type. hushd allows a connection 60 at once and then 5 a second.
- Clients and server share one machine and talk over loopback, so there's no real
  network in these numbers.

The machine: AMD Ryzen 7 7800X3D, Crucial P310 NVMe SSD, btrfs on an encrypted volume,
Linux 7.2, hushd built with gcc 16 at `-O2`.

## On disk

| Clients | Messages each | Deliveries | Time | Deliveries/s | Messages/s | Latency p50 / p99 |
|---|---|---|---|---|---|---|
| 2, 20 a second each | 50 | 200 | 2.46 s | | | 2.0 / 2.2 ms |
| 16, all at once | 50 | 12,800 | 0.60 s | 21,474 | 1,342 | 593 / 596 ms |
| 64, all at once | 20 | 81,920 | 0.99 s | 82,708 | 1,292 | 971 / 990 ms |
| 256, all at once | 10 | 655,360 | 2.13 s | 307,875 | 1,203 | 1,946 / 2,126 ms |
| 512, all at once | 5 | 1,310,720 | 2.38 s | 550,931 | 1,076 | 2,019 / 2,375 ms |

512 clients logged in within 0.61 seconds.

## With the files in memory

The same runs with `-t /tmp`, which is a tmpfs here, so writes never wait for a disk:

| Clients | Messages each | Time | Deliveries/s | Messages/s | Latency p50 / p99 |
|---|---|---|---|---|---|
| 2, 20 a second each | 50 | 2.45 s | | | 0.1 / 0.2 ms |
| 16, all at once | 50 | 0.01 s | 902,740 | 56,421 | 11.7 / 13.8 ms |
| 64, all at once | 20 | 0.05 s | 1,798,839 | 28,107 | 27.2 / 44.8 ms |
| 256, all at once | 10 | 0.39 s | 1,695,376 | 6,623 | 202 / 385 ms |
| 512, all at once | 5 | 0.82 s | 1,593,934 | 3,113 | 456 / 817 ms |

## What it says

Storage is the limit. Each message is its own SQLite transaction, and in WAL mode with
the default `synchronous` setting every commit waits for the disk. On this SSD that's
under a millisecond, which caps hushd at roughly 1,100 to 1,350 stored messages a
second. A burst waits in line: 512 people sending 5 messages each at the same moment
takes about 2.4 seconds to clear. Without the disk, the same single thread delivers
1.6 to 1.8 million copies a second.

That's far more than a group of friends needs. At a normal pace, a message reaches
everyone in about 2 ms, and almost all of that is the disk write.

The catch is that while the single thread waits for the disk, it does nothing else.
One way to fix that would be to commit everything that arrived in one pass of the event
loop as a single transaction, before sending any of it. A message would still never be
delivered before it's stored, and a burst would cost one disk write instead of hundreds.
That isn't built yet.

## A bug it found

The first run showed a 41 ms worst case with only two clients chatting at a relaxed
pace, while the median was 0.1 ms. Neither hushd nor the terminal client set
`TCP_NODELAY`, so a small frame sent while an earlier one was still unacknowledged
waited in the kernel for the other side's delayed ACK, about 40 ms. Both set it now
(`7dab041`), and the worst case for that run dropped to about 2 ms.
