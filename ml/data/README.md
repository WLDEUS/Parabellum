# ml/data

`extra_clean_features.jsonl` (optional, committed by the owner) adds clean Mach-O feature vectors
from the owner's own Mac to the training negatives. Generate it on the Mac with the release build of
`pb-features` (same `features_version` as CI):

```sh
target/release/pb-features --label 0 /Applications /System/Applications /opt/homebrew/bin \
  /usr/local/bin > ml/data/extra_clean_features.jsonl
```

Only feature vectors and SHA-256 are stored (no file content); the `path` field is ignored by the
trainer — strip it if you do not want local paths in the repository:
`python3 -c 'import json,sys;[print(json.dumps({k:v for k,v in json.loads(l).items() if k!="path"})) for l in sys.stdin]'`.
Rows whose `features_version` differs from the current `pb-features` are dropped automatically.

`extra_clean_script_features.jsonl` (optional) does the same for the **script** classifier — the only
practical source of clean AppleScript and macOS system scripts (`/usr/bin`, `/usr/libexec`,
`/Library/Scripts`, oh-my-zsh, dotfiles):

```sh
target/release/pb-features --kind script --label 0 /usr/bin /usr/sbin /usr/libexec /Library/Scripts \
  /System/Library/Scripts /opt/homebrew/bin ~/.oh-my-zsh > ml/data/extra_clean_script_features.jsonl
```

Only feature vectors are kept; strip `path` the same way before committing. Never point it at folders
holding downloaded or untrusted scripts (a malicious script labelled clean poisons the model).
