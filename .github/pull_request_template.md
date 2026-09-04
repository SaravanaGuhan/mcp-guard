## What this changes

<!-- One or two sentences. -->

## Did the golden set change?

- [ ] No. `tests/golden/` is untouched.
- [ ] Yes, and every added and removed line is justified below.

A file move, a refactor, or a performance change must not alter a single
finding. If `tests/golden/` changed for one of those, a path or a code path
broke and the fix is to that, not to the golden set.

If it did legitimately change, paste the LOST/NEW diff the golden test prints
and justify each line individually:

```
LOST: ...   why this detection is gone and why that is correct
NEW:  ...   what observation produces this and why it is right
```

## Checks

- [ ] `make test` passes: 168 or more tests, coverage at or above 78%
- [ ] `make lint` clean
- [ ] `make bench` unchanged, or the change is explained above
- [ ] Every new finding carries evidence a reader can verify
- [ ] No capability claim added to the docs without code that runs

## Anything you could not do

<!-- Say so here rather than leaving it implicit. -->
