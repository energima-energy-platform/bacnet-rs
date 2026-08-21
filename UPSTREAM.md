# Tracking upstream bacnet-rs

This repository is a long-lived fork of [`bacnet-rs/bacnet-rs`](https://github.com/bacnet-rs/bacnet-rs).
It carries substantial work upstream does not have — the BACnet/IP server and
hosted-object dispatch, intrinsic reporting, COV, scheduling, complex property
decoding, and the async client.

**We do not upstream.** The fork is the product; upstream is a source of fixes.

## Policy

Adopt every upstream change **unless it is wrong for us**. A change is wrong for
us when it:

- contradicts a model we deliberately chose (see the tag-model note below), or
- reimplements something the fork already does more completely.

When we decline a change, the merge commit says which change and why. That record
is the point: without it the next person cannot tell a rejection from an oversight.

## Procedure

```sh
git remote add upstream https://github.com/bacnet-rs/bacnet-rs.git   # once
git fetch upstream
git merge upstream/main
```

Merge, never rebase. Rebasing would rewrite every commit in the fork on each
pull, change hashes under anyone's checkout, and re-litigate the same conflicts
every time. The merge commit is also where the policy record lives.

Enable `rerere` so recurring conflict resolutions replay themselves. It is
per-clone configuration and cannot be committed, so each clone needs it:

```sh
git config rerere.enabled true
git config rerere.autoupdate true
```

## Where conflicts land

`src/encoding/mod.rs` and `src/service/mod.rs`. The fork rewrote both, so
upstream edits there rarely apply cleanly.

Watch for duplicates that git merges **without** reporting a conflict: upstream
adding a helper, enum variant, or type the fork already has produces two
definitions in one file. These surface as `error[E0081]`/`E0428` at build time,
not as conflict markers — so always build after a merge, never just check that
the merge succeeded.

### The tag model

The fork's `BACnetTag` has four variants — `Application`, `Context`, `Opening`,
`Closing`. Upstream's has two, so a constructed value's opening marker (`0x2E`,
`0x4E`) and its closing marker (`0x2F`, `0x4F`) both decode to `Context(n)`,
indistinguishable from each other and from a primitive context tag.

Upstream decoders written against that model compare markers to `Context(n)`.
Against ours they return `InvalidTag`. Repoint them to `Opening(n)`/`Closing(n)`,
or decline the change if the fork already covers the service.

## Known pre-existing failures

Not caused by any merge; do not treat them as merge regressions.

- `transport::tests::test_timeout_tracking` — binds a fixed port, fails with
  `AddrInUse`.
- `cargo build --no-default-features` — 132 errors, missing `alloc` imports for
  `vec!` and `format!` in the `no_std` configuration.
