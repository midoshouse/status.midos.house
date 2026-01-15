#!/usr/bin/env pwsh

cargo test
if (-not $?)
{
    throw 'Native Failure'
}

# copy the tree to the WSL file system to improve compile times
wsl -d ubuntu-m2 rsync --mkpath --delete -av /mnt/c/Users/fenhl/git/github.com/midoshouse/status.midos.house/stage/ /home/fenhl/wslgit/github.com/midoshouse/status.midos.house/ --exclude target
if (-not $?)
{
    throw 'Native Failure'
}

wsl -d ubuntu-m2 /home/fenhl/.cargo/bin/rustup update stable
if (-not $?)
{
    throw 'Native Failure'
}

wsl -d ubuntu-m2 env -C /home/fenhl/wslgit/github.com/midoshouse/status.midos.house /home/fenhl/.cargo/bin/cargo check
if (-not $?)
{
    throw 'Native Failure'
}
