/*
Package cmd is the root package.
Copyright © 2022 Thomas Stringer <thomas@trstringer.com>

*/
package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "jwt-creator",
	Short: "Create a JWT quickly and easily",
	Long: `This CLI allows you to quickly and easily
create JWTs.`,
	// Run: func(cmd *cobra.Command, args []string) {},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
