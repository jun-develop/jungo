// Command console executes registered CLI commands.
//
// Usage:
//
//	make console CMD="health:check"
//	make console CMD="db:migrate"
//	make console CMD="health:check --verbose"   (also print app logs and executed SQL)
//	make console CMD="health:check --debug"     (print every log, Fx events included)
package main

import "jungo/internal/app"

func main() {
	app.NewConsoleFx().Run()
}
