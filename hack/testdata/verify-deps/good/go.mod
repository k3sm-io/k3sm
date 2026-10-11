module example.com/fixture

go 1.26

require (
	example.com/forked v1.0.0
	example.com/fresh v1.1.0
	example.com/old v1.2.3
	github.com/Upper/Case v0.0.0-20240101000000-abcdefabcdef
	k3sm.io/apis v0.0.0-00010101000000-000000000000
	k3sm.io/runtimed v0.0.0-00010101000000-000000000000
)

// The fork carries a fix upstream has not released yet.
replace example.com/forked => example.com/forked-fix v1.0.1

// Sibling repos resolve from their checkouts; one comment explains the run.
replace k3sm.io/apis => ../apis

replace k3sm.io/runtimed => ../runtimed
