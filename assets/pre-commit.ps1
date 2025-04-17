#!/usr/bin/env pwsh

cargo test
if (-not $?)
{
    throw 'Native Failure'
}
