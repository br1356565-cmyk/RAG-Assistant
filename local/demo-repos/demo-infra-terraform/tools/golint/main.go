// golint-names checks that service names are valid language tags (demo helper).
package main

import (
	"fmt"
	"os"

	"golang.org/x/text/language"
)

func main() {
	for _, arg := range os.Args[1:] {
		if _, err := language.Parse(arg); err != nil {
			fmt.Printf("%s: %v\n", arg, err)
			os.Exit(1)
		}
	}
	fmt.Println("ok")
}
