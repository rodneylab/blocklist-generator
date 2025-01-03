# find comments in Rust source
comments:
    rg --pcre2 -t rust '(^|\s+)(\/\/|\/\*)\s+(?!(act|arrange|assert))' .

# find expects and unwraps in Rust source
expects:
    rg --pcre2 -t rust '\.(expect\(.*\)|unwrap\(\))' .

# run coverage using grcov
coverage:
    rm -f blocklist_generator-*.profraw 2>/dev/null
    cargo clean
    cargo build
    C_COMPILER=$(brew --prefix llvm)/bin/clang RUSTFLAGS="-Cinstrument-coverage" \
        LLVM_PROFILE_FILE="blocklist_generator-%p-%m.profraw" cargo test
    grcov . -s . --binary-path ./target/debug/ -t html --branch --ignore-not-existing \
        -o ./target/debug/coverage/
    open --reveal ./target/debug/coverage/index.html
    sed -i '' "s|href=\"https://cdn.jsdelivr.net/npm/bulma@0.9.1/css/bulma.min.css\"|href=\"file://`pwd`/.cache/bulma.min.css\"|g" ./target/debug/coverage/**/*.html
    mkdir -p .cache
    curl --time-cond .cache/bulma.min.css -C - -Lo .cache/bulma.min.css \
      https://cdn.jsdelivr.net/npm/bulma/css/bulma.min.css

# generate docs for a crate and copy link to clipboard
doc crate:
    cargo doc -p {{ crate }}
    @echo "`pwd`/target/doc/{{ crate }}/index.html" | pbcopy

# review (accept/reject/...) insta snapshots
insta-snapshot-review:
    cargo insta review

# copy URL for Rust std docs to clipboard
std:
    @rustup doc --std --path | pbcopy
