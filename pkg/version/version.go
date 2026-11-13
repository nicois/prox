// Package version carries the build identity, stamped at link time.
//
// Builds made by the repo Makefile (or any build passing
// -X github.com/nicois/prox/pkg/version.Commit=<hash>) report the git commit they were built
// from; the value is recorded in the "meta" event at the head of every
// captured stream's meta.jsonl and in the journal "starting" line, so a
// stream can always be traced to the build that wrote it. Unstamped builds
// report Dev; the prox CLI refuses to start with one, and the Makefile
// refuses to build without a resolvable commit.
package version

// Dev is the commit value of an unstamped build. The prox CLI refuses
// to start with it (and the Makefile refuses to build without a real
// commit), so a dev binary can only exist in test harnesses.
const Dev = "dev"

// Commit is the git commit (short hash) this binary was built from, or
// Dev when the link-time stamp was not applied.
var Commit = Dev
