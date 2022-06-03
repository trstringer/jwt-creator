/*
Package cmd is the root package.
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/golang-jwt/jwt"
	"github.com/spf13/cobra"
)

var (
	publicKeyFile  string
	publicKeyStdin bool
	tokenRaw       string
)

// verifyCmd represents the verify command
var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify a JWT",
	Run: func(cmd *cobra.Command, args []string) {
		if err := validateVerifyParams(); err != nil {
			fmt.Printf("%v\n", err)
			os.Exit(1)
		}

		var publicKey []byte
		var err error
		if publicKeyFile == "-" || publicKeyStdin {
			publicKey, err = ioutil.ReadAll(os.Stdin)
			if err != nil {
				fmt.Printf("error reading from stdin: %v\n", err)
				os.Exit(1)
			}
		} else {
			publicKey, err = ioutil.ReadFile(publicKeyFile)
			if err != nil {
				fmt.Printf("error reading public key file: %v\n", err)
				os.Exit(1)
			}
		}

		token, err := jwt.Parse(tokenRaw, func(token *jwt.Token) (interface{}, error) {
			// Currently this uses public key from the args but the key
			// can be looked up in a JWKS by the key ID, which can be
			// stored in the token header: token.Header["kid"]

			block, _ := pem.Decode(publicKey)
			if block == nil {
				fmt.Printf("unexpected nil block")
				os.Exit(1)
			}
			pub, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				fmt.Printf("error parsing public key: %v\n", err)
				os.Exit(1)
			}
			rsaPublicKey, ok := pub.(*rsa.PublicKey)
			if !ok {
				fmt.Printf("unexpected not public key")
				os.Exit(1)
			}
			return rsaPublicKey, nil
		})
		if !token.Valid {
			fmt.Printf("invalid token: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("Token is valid")
	},
}

func init() {
	rootCmd.AddCommand(verifyCmd)

	verifyCmd.Flags().StringVar(&publicKeyFile, "public-key-file", "", "Public key file")
	verifyCmd.Flags().BoolVar(&publicKeyStdin, "public-key-stdin", false, "Pass in the public key through stdin")
	verifyCmd.Flags().StringVarP(&tokenRaw, "token", "t", "", "JSON web token")
}

func validateVerifyParams() error {
	if publicKeyFile == "" && !publicKeyStdin {
		return fmt.Errorf("no public key specified")
	}

	if tokenRaw == "" {
		return fmt.Errorf("no token specified")
	}

	return nil
}
