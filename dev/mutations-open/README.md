# Mutations that are expected to survive

Sets in here are **unfinished on purpose**. They are kept out of
`dev/mutations/` so that

    python3 dev/mutate.py dev/mutations

is a green-or-broken signal rather than one that always fails. A gate that
always fails gets ignored - that is how `dev/audit.py` stayed red through three
releases.

Run one by name when you want to work on it:

    python3 dev/mutate.py dev/mutations-open/message-values.json

**`message-values.json`** - every numeric placeholder in a finding message,
replaced by a literal zero. 62 mutations; 43 are caught. The 19 that survive
are helpers, renderers and second sentences, and stopping there was a decision:
none of them is a number a verdict rests on. The reasoning, and the line
numbers, are in `dev/HANDOVER.md`.
